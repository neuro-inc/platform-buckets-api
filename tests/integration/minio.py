import asyncio
import logging
from typing import AsyncIterator, Iterator

import aiobotocore
import aiohttp
import pytest
from aiobotocore.client import AioBaseClient
from async_timeout import timeout
from docker import DockerClient
from docker.errors import NotFound as ContainerNotFound
from docker.models.containers import Container
from yarl import URL

from platform_buckets_api.providers import BMCWrapper


logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def minio_container_image() -> str:
    return "minio/minio:latest"


@pytest.fixture(scope="session")
def minio_container_name() -> str:
    return "platform-buckets-api-minio"


def _create_url(container: Container, in_docker: bool) -> URL:
    exposed_port = 9000
    if in_docker:
        host, port = container.attrs["NetworkSettings"]["IPAddress"], exposed_port
    else:
        host, port = "0.0.0.0", container.ports[f"{exposed_port}/tcp"][0]["HostPort"]
    return URL(f"http://{host}:{port}")


@pytest.fixture(scope="session")
def _minio_server(
    docker_client: DockerClient,
    in_docker: bool,
    reuse_docker: bool,
    minio_container_image: str,
    minio_container_name: str,
) -> Iterator[URL]:

    try:
        container = docker_client.containers.get(minio_container_name)
        if reuse_docker:
            yield _create_url(container, in_docker)
            return
        else:
            container.remove(force=True)
    except ContainerNotFound:
        pass

    # `run` performs implicit `pull`
    container = docker_client.containers.run(
        image=minio_container_image,
        name=minio_container_name,
        publish_all_ports=True,
        stdout=False,
        stderr=False,
        detach=True,
        command=["server", "/data"],
        environment={
            "MINIO_ROOT_USER": "access_key",
            "MINIO_ROOT_PASSWORD": "secret_key",
            "MINIO_REGION_NAME": "region-1",
            "MINIO_STORAGE_CLASS_STANDARD": "EC:4",
        },
    )
    container.reload()

    yield _create_url(container, in_docker)

    if not reuse_docker:
        container.remove(force=True)


async def wait_for_minio_server(
    url: URL, timeout_s: float = 300, interval_s: float = 1
) -> None:
    last_exc = None
    try:
        async with timeout(timeout_s):
            while True:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f"{url}/minio/health/live"):
                            return
                except (AssertionError, OSError, aiohttp.ClientError) as exc:
                    last_exc = exc
                logger.debug(f"waiting for {url}: {last_exc}")
                await asyncio.sleep(interval_s)
    except asyncio.TimeoutError:
        pytest.fail(f"failed to connect to {url}: {last_exc}")


@pytest.fixture()
async def minio_server(_minio_server: URL) -> AsyncIterator[URL]:
    await wait_for_minio_server(_minio_server)
    yield _minio_server


@pytest.fixture()
async def minio_s3(minio_server: URL) -> AsyncIterator[AioBaseClient]:
    session = aiobotocore.get_session()

    async def _drop_buckets(s3: AioBaseClient) -> None:
        for bucket in (await s3.list_buckets())["Buckets"]:
            bucket_name = bucket["Name"]
            for obj in (await s3.list_objects_v2(Bucket=bucket_name)).get(
                "Contents", []
            ):
                obj_key = obj["Key"]
                await s3.delete_object(Bucket=bucket_name, Key=obj_key)
            await s3.delete_bucket(Bucket=bucket_name)

    async with session.create_client(
        "s3",
        endpoint_url=str(minio_server),
        aws_access_key_id="access_key",
        aws_secret_access_key="secret_key",
        region_name="region-1",
    ) as s3_client:
        await _drop_buckets(s3_client)
        yield s3_client
        await _drop_buckets(s3_client)


@pytest.fixture()
async def minio_sts(minio_server: URL) -> AsyncIterator[AioBaseClient]:
    session = aiobotocore.get_session()

    async with session.create_client(
        "sts",
        endpoint_url=str(minio_server),
        aws_access_key_id="access_key",
        aws_secret_access_key="secret_key",
        region_name="region-1",
    ) as s3_client:
        yield s3_client


@pytest.fixture()
async def bmc_wrapper(minio_server: URL) -> AsyncIterator[BMCWrapper]:
    async def _drop_users(mc: BMCWrapper) -> None:
        for user in (await mc.admin_user_list()).content:
            await mc.admin_user_remove(username=user["accessKey"])

    async with BMCWrapper(minio_server, "access_key", "secret_key") as wrapper:
        await _drop_users(wrapper)
        yield wrapper
        await _drop_users(wrapper)
