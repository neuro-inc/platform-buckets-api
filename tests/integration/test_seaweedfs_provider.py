import asyncio
import json
import secrets
from collections.abc import AsyncIterator, Iterator
from contextlib import AsyncExitStack
from datetime import UTC, datetime
from functools import partial

import aiobotocore.session
import pytest
from aiobotocore.client import AioBaseClient
from aiohttp import ClientSession
from docker import DockerClient
from docker.errors import NotFound as ContainerNotFound
from docker.models.containers import Container
from yarl import URL

from platform_buckets_api.providers import (
    BucketPermission,
    SeaweedFSBucketProvider,
    UserBucketOperations,
)
from platform_buckets_api.storage import ImportedBucket
from tests.integration.test_aws_provider import (
    AwsBasicBucketClient,
    aws_bucket_exists,
    aws_role_exists,
)
from tests.integration.test_provider_base import (
    ProviderTestOption,
    TestProviderBase,
    _test_read_access,
    as_admin_cm,
)

IMAGE = "chrislusf/seaweedfs:4.41"
CONTAINER_NAME = "platform-buckets-api-seaweedfs"
ACCESS_KEY = "root"
SECRET_KEY = "root-secret-key"


def _name(suffix: str) -> str:
    return f"integration-tests-{suffix}-{secrets.token_hex(4)}"


def _container_url(container: Container, in_docker: bool) -> URL:
    port = 8333
    if in_docker:
        host = container.attrs["NetworkSettings"]["IPAddress"]
    else:
        host = "127.0.0.1"
        port = int(container.ports["8333/tcp"][0]["HostPort"])
    return URL(f"http://{host}:{port}")


@pytest.fixture(scope="session")
def seaweedfs_container(
    docker_client: DockerClient,
    reuse_docker: bool,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[Container]:
    config_path = tmp_path_factory.mktemp("seaweedfs") / "s3.json"
    config_path.write_text(
        json.dumps(
            {
                "identities": [
                    {
                        "name": "admin",
                        "credentials": [
                            {"accessKey": ACCESS_KEY, "secretKey": SECRET_KEY}
                        ],
                        "actions": ["Admin"],
                        "policyNames": ["PlatformBucketsAdmin"],
                    }
                ],
                "policies": [
                    {
                        "name": "PlatformBucketsAdmin",
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["*"],
                                    "Resource": ["*"],
                                }
                            ],
                        },
                    }
                ],
            }
        )
    )
    try:
        container = docker_client.containers.get(CONTAINER_NAME)
        if reuse_docker:
            yield container
            return
        container.remove(force=True)
    except ContainerNotFound:
        pass

    container = docker_client.containers.run(
        image=IMAGE,
        name=CONTAINER_NAME,
        command=[
            "server",
            "-s3",
            "-s3.config=/etc/seaweedfs/s3.json",
            "-s3.iam.readOnly=false",
        ],
        environment={"WEED_JWT_FILER_SIGNING_KEY": "integration-test-signing-key"},
        volumes={str(config_path): {"bind": "/etc/seaweedfs/s3.json", "mode": "ro"}},
        publish_all_ports=True,
        detach=True,
    )
    container.reload()
    try:
        yield container
    finally:
        if not reuse_docker:
            container.remove(force=True)


@pytest.fixture(scope="session")
def seaweedfs_url(seaweedfs_container: Container, in_docker: bool) -> URL:
    return _container_url(seaweedfs_container, in_docker)


async def _wait_until_ready(url: URL, timeout: float = 120) -> None:
    async with asyncio.timeout(timeout):
        while True:
            try:
                session = aiobotocore.session.get_session()
                async with session.create_client(
                    "s3",
                    endpoint_url=str(url),
                    aws_access_key_id=ACCESS_KEY,
                    aws_secret_access_key=SECRET_KEY,
                    region_name="us-east-1",
                ) as client:
                    await client.list_buckets()
                    return
            except Exception:
                await asyncio.sleep(0.5)


async def _make_clients(
    stack: AsyncExitStack, url: URL
) -> tuple[AioBaseClient, AioBaseClient, AioBaseClient]:
    session = aiobotocore.session.get_session()
    kwargs = {
        "endpoint_url": str(url),
        "aws_access_key_id": ACCESS_KEY,
        "aws_secret_access_key": SECRET_KEY,
        "region_name": "us-east-1",
    }
    s3 = await stack.enter_async_context(session.create_client("s3", **kwargs))
    iam = await stack.enter_async_context(session.create_client("iam", **kwargs))
    sts = await stack.enter_async_context(session.create_client("sts", **kwargs))
    return s3, iam, sts


class TestSeaweedFSProvider(TestProviderBase):
    __test__ = True

    @pytest.fixture()
    async def provider_option(
        self, seaweedfs_url: URL
    ) -> AsyncIterator[ProviderTestOption]:
        await _wait_until_ready(seaweedfs_url)
        async with AsyncExitStack() as stack:
            s3, iam, sts = await _make_clients(stack, seaweedfs_url)
            public_url = seaweedfs_url.with_host("localhost")
            session = aiobotocore.session.get_session()
            public_s3 = await stack.enter_async_context(
                session.create_client(
                    "s3",
                    endpoint_url=str(public_url),
                    aws_access_key_id=ACCESS_KEY,
                    aws_secret_access_key=SECRET_KEY,
                    region_name="us-east-1",
                )
            )
            provider = SeaweedFSBucketProvider(
                s3_client=s3,
                iam_client=iam,
                sts_client=sts,
                public_url=public_url,
                public_s3_client=public_s3,
            )
            yield ProviderTestOption(
                type="seaweedfs",
                provider=provider,
                bucket_exists=partial(aws_bucket_exists, s3),
                make_client=AwsBasicBucketClient.create,
                get_admin=as_admin_cm(
                    lambda bucket: AwsBasicBucketClient(s3, bucket.name)
                ),
                role_exists=partial(aws_role_exists, iam),
                get_public_url=lambda bucket_name, key: public_url / bucket_name / key,
                credentials_for_imported={
                    "endpoint_url": str(public_url),
                    "access_key_id": ACCESS_KEY,
                    "secret_access_key": SECRET_KEY,
                    "region_name": "us-east-1",
                },
            )

    async def test_bucket_credentials_read_access(
        self, provider_option: ProviderTestOption
    ) -> None:
        bucket = await provider_option.provider.create_bucket(_name("temporary-read"))
        credentials = await provider_option.provider.get_bucket_credentials(
            bucket, write=False, requester="testing"
        )
        async with (
            provider_option.make_client(bucket, credentials) as user_client,
            provider_option.get_admin(bucket) as admin,
        ):
            await _test_read_access(admin, user_client)

    async def test_role_grant_bucket_read_only_access(
        self, provider_option: ProviderTestOption
    ) -> None:
        bucket = await provider_option.provider.create_bucket(_name("role-read"))
        role = await provider_option.provider.create_role(
            _name("read-role"),
            [BucketPermission(bucket_name=bucket.name, write=False)],
        )
        async with (
            provider_option.make_client(bucket, role.credentials) as user_client,
            provider_option.get_admin(bucket) as admin,
        ):
            await _test_read_access(admin, user_client)

    async def test_signed_url_for_imported_bucket(
        self, provider_option: ProviderTestOption
    ) -> None:
        bucket = await provider_option.provider.create_bucket(
            _name("imported-signed-url")
        )
        async with provider_option.get_admin(bucket) as admin:
            await admin.put_object("signed.txt", b"signed data")

        async with UserBucketOperations.get_for_imported_bucket(
            ImportedBucket(
                id="not-important",
                created_at=datetime.now(UTC),
                owner="user",
                name="not-important",
                org_name="test-org",
                project_name="test-project",
                public=False,
                provider_bucket=bucket,
                credentials=provider_option.credentials_for_imported,
            )
        ) as operations:
            signed_url = await operations.sign_url_for_blob(bucket, "signed.txt")

        assert signed_url.query.get("Signature") or signed_url.query.get(
            "X-Amz-Signature"
        )
        async with ClientSession() as session:
            async with session.get(signed_url) as response:
                assert response.status == 200
                assert await response.read() == b"signed data"

    async def test_temporary_credentials_are_bucket_scoped(
        self, provider_option: ProviderTestOption
    ) -> None:
        allowed_bucket = await provider_option.provider.create_bucket(
            _name("temporary-allowed")
        )
        denied_bucket = await provider_option.provider.create_bucket(
            _name("temporary-denied")
        )
        credentials = await provider_option.provider.get_bucket_credentials(
            allowed_bucket, write=True, requester="testing"
        )

        async with provider_option.make_client(
            denied_bucket, credentials
        ) as denied_client:
            with pytest.raises(Exception):
                await denied_client.put_object("denied.txt", b"denied")

    async def test_public_access_can_be_revoked(
        self, provider_option: ProviderTestOption
    ) -> None:
        bucket = await provider_option.provider.create_bucket(_name("public-revoke"))
        async with provider_option.get_admin(bucket) as admin:
            await admin.put_object("public.txt", b"public data")

        url = provider_option.get_public_url(bucket.name, "public.txt")
        await provider_option.provider.set_public_access(bucket.name, True)
        async with ClientSession() as session, session.get(url) as response:
            assert response.status == 200

        await provider_option.provider.set_public_access(bucket.name, False)
        async with ClientSession() as session, session.get(url) as response:
            assert response.status == 403

    async def test_bucket_cors_preflight(
        self, provider_option: ProviderTestOption
    ) -> None:
        bucket = await provider_option.provider.create_bucket(_name("cors"))
        url = provider_option.get_public_url(bucket.name, "object.txt")

        async with (
            ClientSession() as session,
            session.options(
                url,
                headers={
                    "Origin": "https://example.com",
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": "content-type",
                },
            ) as response,
        ):
            assert response.status == 200
            assert (
                response.headers["Access-Control-Allow-Origin"] == "https://example.com"
            )
            assert "PUT" in response.headers["Access-Control-Allow-Methods"]
