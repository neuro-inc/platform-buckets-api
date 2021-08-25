from contextlib import asynccontextmanager
from typing import AsyncContextManager, AsyncIterator, Callable, Mapping

import aiobotocore
import botocore.exceptions
import pytest
from aiobotocore.client import AioBaseClient

from platform_buckets_api.providers import (
    AWSBucketProvider,
    BucketDeleteError,
    BucketExistsError,
    BucketPermission,
    RoleExistsError,
)
from platform_buckets_api.storage import ProviderBucket
from tests.integration.conftest import MotoConfig


pytestmark = pytest.mark.asyncio


@pytest.fixture()
def aws_provider(
    s3: AioBaseClient, iam: AioBaseClient, sts: AioBaseClient, s3_role: str
) -> AWSBucketProvider:
    return AWSBucketProvider(s3, iam, sts, s3_role)


async def test_bucket_create(
    aws_provider: AWSBucketProvider, s3: AioBaseClient
) -> None:
    bucket = await aws_provider.create_bucket("integration-test-bucket")
    assert bucket.name == "integration-test-bucket"
    buckets = await s3.list_buckets()
    assert buckets["Buckets"][0]["Name"] == "integration-test-bucket"


async def test_bucket_duplicate_create(
    aws_provider: AWSBucketProvider, s3: AioBaseClient
) -> None:
    await aws_provider.create_bucket("integration-test-bucket")
    with pytest.raises(BucketExistsError):
        await aws_provider.create_bucket("integration-test-bucket")


async def test_bucket_delete(
    aws_provider: AWSBucketProvider, s3: AioBaseClient
) -> None:
    bucket = await aws_provider.create_bucket("integration-test-bucket")
    await aws_provider.delete_bucket(bucket.name)
    buckets = await s3.list_buckets()
    assert buckets["Buckets"] == []


async def test_bucket_delete_unknown(
    aws_provider: AWSBucketProvider, s3: AioBaseClient
) -> None:
    with pytest.raises(BucketDeleteError):
        await aws_provider.delete_bucket("integration-test-bucket")


async def test_bucket_delete_not_empty(
    aws_provider: AWSBucketProvider, s3: AioBaseClient
) -> None:
    bucket = await aws_provider.create_bucket("integration-test-bucket")
    await s3.put_object(
        Bucket=bucket.name,
        Key="test",
        Body=b"42",
    )
    with pytest.raises(BucketDeleteError):
        await aws_provider.delete_bucket("integration-test-bucket")


CredentialsClientFactory = Callable[
    [Mapping[str, str]], AsyncContextManager[AioBaseClient]
]


@pytest.fixture()
async def make_s3_client_from_credentials(
    moto_server: MotoConfig,
) -> CredentialsClientFactory:
    @asynccontextmanager
    async def _factory(credentials: Mapping[str, str]) -> AsyncIterator[AioBaseClient]:
        session = aiobotocore.get_session()
        async with session.create_client(
            "s3",
            endpoint_url=str(moto_server.url),
            aws_access_key_id=credentials["access_key_id"],
            aws_secret_access_key=credentials["secret_access_key"],
            aws_session_token=credentials.get("session_token"),
        ) as users_s3_client:
            yield users_s3_client

    return _factory


async def test_role_create(
    aws_provider: AWSBucketProvider,
    iam: AioBaseClient,
    make_s3_client_from_credentials: CredentialsClientFactory,
) -> None:
    role = await aws_provider.create_role("integration_test_role")
    user_resp = await iam.get_user(UserName="integration_test_role")
    assert user_resp["User"]["UserName"] == "integration_test_role"
    assert user_resp["User"]["UserName"] == role.name

    async with make_s3_client_from_credentials(role.credentials) as users_s3:
        with pytest.raises(botocore.exceptions.ClientError) as ex:
            await users_s3.list_buckets()
        assert ex.value.response["Error"]["Code"] == "AccessDenied"


async def test_role_duplicate(aws_provider: AWSBucketProvider) -> None:
    await aws_provider.create_role("integration_test_role")
    with pytest.raises(RoleExistsError):
        await aws_provider.create_role("integration_test_role")


async def test_role_delete(aws_provider: AWSBucketProvider, iam: AioBaseClient) -> None:
    role = await aws_provider.create_role("integration_test_role")
    await aws_provider.delete_role(role.name)
    users = await iam.list_users()
    user_names = {user["UserName"] for user in users["Users"]}
    assert role.name not in user_names


async def test_role_delete_with_permissions(
    aws_provider: AWSBucketProvider, iam: AioBaseClient
) -> None:
    role = await aws_provider.create_role("integration_test_role")
    await aws_provider.set_role_permissions(
        role,
        [
            BucketPermission(
                bucket_name="",
                write=True,
                is_prefix=True,
            )
        ],
    )
    await aws_provider.delete_role(role.name)
    users = await iam.list_users()
    user_names = {user["UserName"] for user in users["Users"]}
    assert role.name not in user_names


async def _test_no_access(
    make_s3_client_from_credentials: CredentialsClientFactory,
    admin_s3: AioBaseClient,
    credentials: Mapping[str, str],
    bucket: ProviderBucket,
) -> None:
    async with make_s3_client_from_credentials(credentials) as users_s3:
        data = b"\x01" * 1024
        key = "foo"

        with pytest.raises(botocore.exceptions.ClientError):
            await users_s3.put_object(
                Bucket=bucket.name,
                Key=key,
                Body=data,
            )
        await admin_s3.put_object(
            Bucket=bucket.name,
            Key=key,
            Body=data,
        )

        with pytest.raises(botocore.exceptions.ClientError):
            await users_s3.get_object(Bucket=bucket.name, Key=key)

        with pytest.raises(botocore.exceptions.ClientError):
            paginator = users_s3.get_paginator("list_objects")
            async for _ in paginator.paginate(Bucket=bucket.name):
                pass

        with pytest.raises(botocore.exceptions.ClientError):
            await users_s3.delete_object(Bucket=bucket.name, Key=key)


async def _test_write_access(
    make_s3_client_from_credentials: CredentialsClientFactory,
    credentials: Mapping[str, str],
    bucket: ProviderBucket,
) -> None:
    async with make_s3_client_from_credentials(credentials) as users_s3:
        data = b"\x01" * 1024
        key = "foo"
        await users_s3.put_object(
            Bucket=bucket.name,
            Key=key,
            Body=data,
        )

        response = await users_s3.get_object(Bucket=bucket.name, Key=key)
        async with response["Body"] as stream:
            assert await stream.read() == data

        keys = []
        paginator = users_s3.get_paginator("list_objects")
        async for result in paginator.paginate(Bucket=bucket.name):
            for c in result.get("Contents", []):
                keys.append(c["Key"])
        assert keys == [key]

        await users_s3.delete_object(Bucket=bucket.name, Key=key)

        keys = []
        paginator = users_s3.get_paginator("list_objects")
        async for result in paginator.paginate(Bucket=bucket.name):
            for c in result.get("Contents", []):
                keys.append(c["Key"])
        assert keys == []


async def _test_read_access(
    make_s3_client_from_credentials: CredentialsClientFactory,
    admin_s3: AioBaseClient,
    credentials: Mapping[str, str],
    bucket: ProviderBucket,
) -> None:
    async with make_s3_client_from_credentials(credentials) as users_s3:
        data = b"\x01" * 1024
        key = "foo"
        with pytest.raises(botocore.exceptions.ClientError):
            await users_s3.put_object(
                Bucket=bucket.name,
                Key=key,
                Body=data,
            )
        await admin_s3.put_object(
            Bucket=bucket.name,
            Key=key,
            Body=data,
        )

        response = await users_s3.get_object(Bucket=bucket.name, Key=key)
        async with response["Body"] as stream:
            assert await stream.read() == data

        keys = []
        paginator = users_s3.get_paginator("list_objects")
        async for result in paginator.paginate(Bucket=bucket.name):
            for c in result.get("Contents", []):
                keys.append(c["Key"])
        assert keys == [key]

        with pytest.raises(botocore.exceptions.ClientError):
            await users_s3.delete_object(Bucket=bucket.name, Key=key)


async def test_bucket_credentials_write_access(
    aws_provider: AWSBucketProvider,
    make_s3_client_from_credentials: CredentialsClientFactory,
) -> None:
    bucket = await aws_provider.create_bucket("integration-test-bucket")
    credentials = await aws_provider.get_bucket_credentials(
        bucket.name, write=True, requester="testing"
    )
    await _test_write_access(make_s3_client_from_credentials, credentials, bucket)


@pytest.mark.skip("Moto do not support embedding policies into token")
async def test_bucket_credentials_read_access(
    aws_provider: AWSBucketProvider,
    s3: AioBaseClient,
    make_s3_client_from_credentials: CredentialsClientFactory,
) -> None:
    bucket = await aws_provider.create_bucket("integration-test-bucket")
    credentials = await aws_provider.get_bucket_credentials(
        bucket.name, write=False, requester="testing"
    )
    await _test_read_access(make_s3_client_from_credentials, s3, credentials, bucket)


async def test_role_grant_bucket_write_access(
    aws_provider: AWSBucketProvider,
    make_s3_client_from_credentials: CredentialsClientFactory,
) -> None:
    role = await aws_provider.create_role("integration_test_role")
    bucket = await aws_provider.create_bucket("integration-test-bucket")
    await aws_provider.set_role_permissions(
        role,
        [
            BucketPermission(
                bucket_name=bucket.name,
                write=True,
            )
        ],
    )
    await _test_write_access(make_s3_client_from_credentials, role.credentials, bucket)


async def test_role_grant_bucket_read_only_access(
    aws_provider: AWSBucketProvider,
    make_s3_client_from_credentials: CredentialsClientFactory,
    s3: AioBaseClient,
) -> None:
    role = await aws_provider.create_role("integration_test_role")
    bucket = await aws_provider.create_bucket("integration-test-bucket")
    await aws_provider.set_role_permissions(
        role,
        [
            BucketPermission(
                bucket_name=bucket.name,
                write=False,
            )
        ],
    )
    await _test_read_access(
        make_s3_client_from_credentials, s3, role.credentials, bucket
    )


async def test_role_grant_access_second_time(
    aws_provider: AWSBucketProvider,
    make_s3_client_from_credentials: CredentialsClientFactory,
) -> None:
    role = await aws_provider.create_role("integration_test_role")
    bucket1 = await aws_provider.create_bucket("integration-test-bucket_1")
    await aws_provider.set_role_permissions(
        role,
        [
            BucketPermission(
                bucket_name=bucket1.name,
                write=True,
            )
        ],
    )
    await _test_write_access(make_s3_client_from_credentials, role.credentials, bucket1)
    bucket2 = await aws_provider.create_bucket("integration-test-bucket_2")
    await aws_provider.set_role_permissions(
        role,
        [
            BucketPermission(
                bucket_name=bucket1.name,
                write=True,
            ),
            BucketPermission(
                bucket_name=bucket2.name,
                write=True,
            ),
        ],
    )
    await _test_write_access(make_s3_client_from_credentials, role.credentials, bucket1)
    await _test_write_access(make_s3_client_from_credentials, role.credentials, bucket2)


async def test_role_downgrade_access(
    aws_provider: AWSBucketProvider,
    s3: AioBaseClient,
    make_s3_client_from_credentials: CredentialsClientFactory,
) -> None:
    role = await aws_provider.create_role("integration_test_role")
    bucket = await aws_provider.create_bucket("integration-test-bucket_1")
    await aws_provider.set_role_permissions(
        role,
        [
            BucketPermission(
                bucket_name=bucket.name,
                write=True,
            )
        ],
    )
    await _test_write_access(make_s3_client_from_credentials, role.credentials, bucket)
    await aws_provider.set_role_permissions(
        role,
        [
            BucketPermission(
                bucket_name=bucket.name,
                write=False,
            ),
        ],
    )
    await _test_read_access(
        make_s3_client_from_credentials, s3, role.credentials, bucket
    )
    await aws_provider.set_role_permissions(
        role,
        [],
    )
    await _test_no_access(make_s3_client_from_credentials, s3, role.credentials, bucket)
