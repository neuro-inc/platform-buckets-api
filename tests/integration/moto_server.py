import asyncio
import json
import logging
import os
from collections.abc import AsyncIterator, Iterator

import aiobotocore.session
import aiohttp
import pytest
from aiobotocore.client import AioBaseClient
from async_timeout import timeout
from docker import DockerClient
from docker.errors import NotFound as ContainerNotFound
from docker.models.containers import Container
from yarl import URL

from tests.integration.conftest import MotoConfig

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def moto_container_image() -> str:
    return "romasku/moto-patched"


@pytest.fixture(scope="session")
def moto_container_name() -> str:
    return "platform-buckets-api-moto-server"


@pytest.fixture(scope="session")
def auth_jwt_secret() -> str:
    return os.environ.get("NP_JWT_SECRET", "secret")


def _create_url(container: Container, in_docker: bool) -> URL:
    exposed_port = 5000
    if in_docker:
        host, port = container.attrs["NetworkSettings"]["IPAddress"], exposed_port
    else:
        host, port = "0.0.0.0", container.ports[f"{exposed_port}/tcp"][0]["HostPort"]
    return URL(f"http://{host}:{port}")


@pytest.fixture(scope="session")
def _auth_url() -> URL:
    return URL(os.environ.get("AUTH_URL", ""))


@pytest.fixture(scope="session")
def _moto_server(
    docker_client: DockerClient,
    in_docker: bool,
    reuse_docker: bool,
    moto_container_image: str,
    moto_container_name: str,
) -> Iterator[URL]:

    try:
        container = docker_client.containers.get(moto_container_name)
        if reuse_docker:
            yield _create_url(container, in_docker)
            return
        else:
            container.remove(force=True)
    except ContainerNotFound:
        pass

    # `run` performs implicit `pull`
    container = docker_client.containers.run(
        image=moto_container_image,
        name=moto_container_name,
        publish_all_ports=True,
        stdout=False,
        stderr=False,
        detach=True,
        environment={"INITIAL_NO_AUTH_ACTION_COUNT": 1},
    )
    container.reload()

    yield _create_url(container, in_docker)

    if not reuse_docker:
        container.remove(force=True)


async def wait_for_moto_server(
    url: URL, timeout_s: float = 300, interval_s: float = 1
) -> None:
    last_exc = None
    try:
        async with timeout(timeout_s):
            while True:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f"{url}/moto-api/"):
                            return
                except (AssertionError, OSError, aiohttp.ClientError) as exc:
                    last_exc = exc
                logger.debug(f"waiting for {url}: {last_exc}")
                await asyncio.sleep(interval_s)
    except asyncio.TimeoutError:
        pytest.fail(f"failed to connect to {url}: {last_exc}")


@pytest.fixture()
async def moto_server(_moto_server: URL) -> AsyncIterator[MotoConfig]:
    await wait_for_moto_server(_moto_server)
    async with aiohttp.ClientSession() as session:
        async with session.post(f"{_moto_server}/moto-api/reset"):
            pass
        async with session.post(f"{_moto_server}/moto-api/reset-auth", data=b"4"):
            pass
    boto_session = aiobotocore.session.get_session()
    async with boto_session.create_client("iam", endpoint_url=str(_moto_server)) as iam:
        create_user_resp = await iam.create_user(UserName="admin")
        keys = (await iam.create_access_key(UserName="admin"))["AccessKey"]
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": "*"}],
        }
        policy_arn = (
            await iam.create_policy(
                PolicyName="admin_policy", PolicyDocument=json.dumps(policy_document)
            )
        )["Policy"]["Arn"]
        await iam.attach_user_policy(UserName="admin", PolicyArn=policy_arn)
    yield MotoConfig(
        url=_moto_server,
        admin_user_arn=create_user_resp["User"]["Arn"],
        admin_access_key_id=keys["AccessKeyId"],
        admin_secret_access_key=keys["SecretAccessKey"],
    )


@pytest.fixture()
async def s3(moto_server: MotoConfig) -> AsyncIterator[AioBaseClient]:
    session = aiobotocore.session.get_session()

    async with session.create_client(
        "s3",
        endpoint_url=str(moto_server.url),
        aws_access_key_id=moto_server.admin_access_key_id,
        aws_secret_access_key=moto_server.admin_secret_access_key,
    ) as s3_client:
        yield s3_client


@pytest.fixture()
async def iam(moto_server: MotoConfig) -> AsyncIterator[AioBaseClient]:
    session = aiobotocore.session.get_session()

    async with session.create_client(
        "iam",
        endpoint_url=str(moto_server.url),
        aws_access_key_id=moto_server.admin_access_key_id,
        aws_secret_access_key=moto_server.admin_secret_access_key,
    ) as iam_client:
        yield iam_client


@pytest.fixture()
async def sts(moto_server: MotoConfig) -> AsyncIterator[AioBaseClient]:
    session = aiobotocore.session.get_session()

    async with session.create_client(
        "sts",
        endpoint_url=str(moto_server.url),
        aws_access_key_id=moto_server.admin_access_key_id,
        aws_secret_access_key=moto_server.admin_secret_access_key,
    ) as iam_client:
        yield iam_client
