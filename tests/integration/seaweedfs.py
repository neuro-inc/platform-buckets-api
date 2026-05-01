import asyncio
import logging
from asyncio import timeout
from collections.abc import AsyncIterator, Iterator

import aiobotocore.session
import aiohttp
import pytest
from aiobotocore.client import AioBaseClient
from docker import DockerClient
from docker.errors import NotFound as ContainerNotFound
from docker.models.containers import Container
from yarl import URL

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def seaweedfs_container_image() -> str:
    return "chrislusf/seaweedfs:latest"


@pytest.fixture(scope="session")
def seaweedfs_container_name() -> str:
    return "platform-buckets-api-seaweedfs-s3"


def _create_url(container: Container, in_docker: bool) -> URL:
    exposed_port = 9000
    if in_docker:
        host, port = container.attrs["NetworkSettings"]["IPAddress"], exposed_port
    else:
        host, port = "0.0.0.0", container.ports[f"{exposed_port}/tcp"][0]["HostPort"]
    return URL(f"http://{host}:{port}")


@pytest.fixture(scope="session")
def _seaweedfs_server(
    docker_client: DockerClient,
    in_docker: bool,
    reuse_docker: bool,
    seaweedfs_container_image: str,
    seaweedfs_container_name: str,
) -> Iterator[URL]:
    try:
        container = docker_client.containers.get(seaweedfs_container_name)
        if reuse_docker:
            yield _create_url(container, in_docker)
            return
        else:
            container.remove(force=True)
    except ContainerNotFound:
        pass

    container = docker_client.containers.run(
        image=seaweedfs_container_image,
        name=seaweedfs_container_name,
        publish_all_ports=True,
        stdout=False,
        stderr=False,
        detach=True,
        command=[
            "/bin/sh",
            "-c",
            "weed server -s3 -s3.port=9000 -dir=/data -ip=0.0.0.0 -s3.allow_empty_buckets",
        ],
        environment={
            "WEED_S3_ADMIN_ACCESS_KEY": "admin",
            "WEED_S3_ADMIN_SECRET_KEY": "devsecret",
        },
    )
    container.reload()

    yield _create_url(container, in_docker)

    if not reuse_docker:
        container.remove(force=True)


async def wait_for_seaweedfs_server(
    url: URL, timeout_s: float = 300, interval_s: float = 1
) -> None:
    last_exc = None
    try:
        async with timeout(timeout_s):
            while True:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(str(url)):
                            return
                except (AssertionError, OSError, aiohttp.ClientError) as exc:
                    last_exc = exc
                logger.debug(f"waiting for {url}: {last_exc}")
                await asyncio.sleep(interval_s)
    except TimeoutError:
        pytest.fail(f"failed to connect to {url}: {last_exc}")


@pytest.fixture()
async def seaweedfs_server(_seaweedfs_server: URL) -> AsyncIterator[URL]:
    await wait_for_seaweedfs_server(_seaweedfs_server)
    yield _seaweedfs_server


@pytest.fixture()
async def seaweedfs_s3(seaweedfs_server: URL) -> AsyncIterator[AioBaseClient]:
    session = aiobotocore.session.get_session()

    async with session.create_client(
        "s3",
        endpoint_url=str(seaweedfs_server),
        aws_access_key_id="admin",
        aws_secret_access_key="devsecret",
        region_name="us-east-1",
    ) as s3_client:
        yield s3_client


@pytest.fixture()
async def seaweedfs_iam(seaweedfs_server: URL) -> AsyncIterator[AioBaseClient]:
    session = aiobotocore.session.get_session()

    async with session.create_client(
        "iam",
        endpoint_url=str(seaweedfs_server),
        aws_access_key_id="admin",
        aws_secret_access_key="devsecret",
        region_name="us-east-1",
    ) as iam_client:
        yield iam_client
