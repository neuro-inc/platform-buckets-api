import json
import logging
import secrets
import subprocess
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import aiohttp
import aiohttp.web
import pytest
from aiobotocore.client import AioBaseClient
from yarl import URL

from platform_buckets_api.config import (
    AWSProviderConfig,
    Config,
    KubeConfig,
    MinioProviderConfig,
    PlatformAuthConfig,
    ServerConfig,
)

logger = logging.getLogger(__name__)


pytest_plugins = [
    "tests.integration.docker",
    "tests.integration.auth",
    "tests.integration.moto_server",
    "tests.integration.minio",
    "tests.integration.kube",
]


def random_name(length: int = 6) -> str:
    return secrets.token_hex(length // 2 + length % 2)[:length]


@pytest.fixture
async def client() -> AsyncIterator[aiohttp.ClientSession]:
    async with aiohttp.ClientSession() as session:
        yield session


@dataclass(frozen=True)
class MotoConfig:
    url: URL
    region_name: str
    admin_user_arn: str
    admin_access_key_id: str
    admin_secret_access_key: str


@pytest.fixture()
async def s3_role(iam: AioBaseClient, moto_server: MotoConfig) -> str:
    assume_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": moto_server.admin_user_arn,
                },
                "Action": "sts:AssumeRole",
                "Condition": {},
            }
        ],
    }
    resp = await iam.create_role(
        RoleName="s3-role", AssumeRolePolicyDocument=json.dumps(assume_doc)
    )
    await iam.attach_role_policy(
        RoleName="s3-role", PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess"
    )
    return resp["Role"]["Arn"]


@pytest.fixture
def config_factory(
    auth_config: PlatformAuthConfig,
    cluster_name: str,
    kube_config: KubeConfig,
    moto_server: MotoConfig,
    kube_client: None,  # Force cleanup
    s3_role: str,
) -> Callable[..., Config]:
    def _f(**kwargs: Any) -> Config:
        defaults = {
            "server": ServerConfig(host="0.0.0.0", port=8080),
            "platform_auth": auth_config,
            "kube": kube_config,
            "cluster_name": cluster_name,
            "bucket_provider": AWSProviderConfig(
                endpoint_url=moto_server.url,
                access_key_id=moto_server.admin_access_key_id,
                secret_access_key=moto_server.admin_secret_access_key,
                s3_role_arn=s3_role,
            ),
        }
        kwargs = {**defaults, **kwargs}
        return Config(**kwargs)

    return _f


@pytest.fixture(params=["aws-moto", "minio"])
def config(
    request: Any,
    config_factory: Callable[..., Config],
    moto_server: MotoConfig,
    minio_server: URL,
) -> Config:
    if request.param == "aws-moto":
        return config_factory()  # Moto is by default
    elif request.param == "minio":
        return config_factory(
            bucket_provider=MinioProviderConfig(
                endpoint_url=minio_server,
                endpoint_public_url=minio_server,
                access_key_id="access_key",
                secret_access_key="secret_key",
                region_name="region-1",
            )
        )
    raise Exception(f"Unknown bucket provider {request.param}.")


@pytest.fixture()
def config_creation_disabled(
    config_factory: Callable[..., Config],
) -> Config:
    return config_factory(disable_creation=True)


@dataclass(frozen=True)
class ApiAddress:
    host: str
    port: int


@asynccontextmanager
async def create_local_app_server(
    app: aiohttp.web.Application, port: int = 8080
) -> AsyncIterator[ApiAddress]:
    runner = aiohttp.web.AppRunner(app)
    try:
        await runner.setup()
        api_address = ApiAddress("0.0.0.0", port)
        site = aiohttp.web.TCPSite(runner, api_address.host, api_address.port)
        await site.start()
        yield api_address
    finally:
        await runner.shutdown()
        await runner.cleanup()


def get_service_url(service_name: str, namespace: str = "default") -> str:
    # ignore type because the linter does not know that `pytest.fail` throws an
    # exception, so it requires to `return None` explicitly, so that the method
    # will return `Optional[List[str]]` which is incorrect
    timeout_s = 60
    interval_s = 10

    while timeout_s:
        process = subprocess.run(
            ("minikube", "service", "-n", namespace, service_name, "--url"),
            stdout=subprocess.PIPE,
        )
        output = process.stdout
        if output:
            url = output.decode().strip()
            # Sometimes `minikube service ... --url` returns a prefixed
            # string such as: "* https://127.0.0.1:8081/"
            start_idx = url.find("http")
            if start_idx > 0:
                url = url[start_idx:]
            return url
        time.sleep(interval_s)
        timeout_s -= interval_s

    pytest.fail(f"Service {service_name} is unavailable.")


@pytest.fixture
def cluster_name() -> str:
    return "test-cluster"
