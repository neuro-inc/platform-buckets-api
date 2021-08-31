from contextlib import asynccontextmanager
from typing import AsyncIterator, Mapping

import aiobotocore
import botocore.exceptions
import pytest
from aiobotocore.client import AioBaseClient
from yarl import URL

from platform_buckets_api.providers import (
    BMCWrapper,
    BucketExistsError,
    BucketNotExistsError,
    BucketPermission,
    MinioBucketProvider,
    RoleExistsError,
)
from platform_buckets_api.storage import ProviderBucket


pytestmark = pytest.mark.asyncio


@pytest.fixture()
def minio_provider(
    minio_s3: AioBaseClient, minio_sts: AioBaseClient, bmc_wrapper: BMCWrapper
) -> MinioBucketProvider:
    return MinioBucketProvider(minio_s3, minio_sts, bmc_wrapper)


async def test_bucket_create(
    minio_provider: MinioBucketProvider, minio_s3: AioBaseClient
) -> None:
    bucket = await minio_provider.create_bucket("integration-test-bucket")
    assert bucket.name == "integration-test-bucket"
    buckets = await minio_s3.list_buckets()
    assert buckets["Buckets"][0]["Name"] == "integration-test-bucket"


async def test_bucket_duplicate_create(
    minio_provider: MinioBucketProvider, minio_s3: AioBaseClient
) -> None:
    await minio_provider.create_bucket("integration-test-bucket")
    with pytest.raises(BucketExistsError):
        await minio_provider.create_bucket("integration-test-bucket")


async def test_bucket_delete(
    minio_provider: MinioBucketProvider, minio_s3: AioBaseClient
) -> None:
    bucket = await minio_provider.create_bucket("integration-test-bucket")
    await minio_provider.delete_bucket(bucket.name)
    buckets = await minio_s3.list_buckets()
    assert buckets["Buckets"] == []


async def test_bucket_delete_unknown(
    minio_provider: MinioBucketProvider, minio_s3: AioBaseClient
) -> None:
    with pytest.raises(BucketNotExistsError):
        await minio_provider.delete_bucket("integration-test-bucket")


@asynccontextmanager
async def make_s3_client_from_credentials(
    credentials: Mapping[str, str]
) -> AsyncIterator[AioBaseClient]:
    session = aiobotocore.get_session()
    async with session.create_client(
        "s3",
        endpoint_url=credentials["endpoint_url"],
        region_name=credentials["region_name"],
        aws_access_key_id=credentials["access_key_id"],
        aws_secret_access_key=credentials["secret_access_key"],
        aws_session_token=credentials.get("session_token"),
    ) as users_s3_client:
        yield users_s3_client


async def test_role_create(
    minio_provider: MinioBucketProvider,
    bmc_wrapper: BMCWrapper,
) -> None:
    role = await minio_provider.create_role("integration_test_role")
    resp = await bmc_wrapper.admin_user_info(username="integration_test_role")
    assert resp.content["status"] == "success"

    async with make_s3_client_from_credentials(role.credentials) as users_s3:
        with pytest.raises(botocore.exceptions.ClientError) as ex:
            await users_s3.list_buckets()
        assert ex.value.response["Error"]["Code"] == "AccessDenied"


async def test_role_duplicate(
    minio_provider: MinioBucketProvider,
) -> None:
    await minio_provider.create_role("integration_test_role")
    with pytest.raises(RoleExistsError):
        await minio_provider.create_role("integration_test_role")


async def test_role_delete(
    minio_provider: MinioBucketProvider, bmc_wrapper: BMCWrapper
) -> None:
    role = await minio_provider.create_role("integration_test_role")
    await minio_provider.delete_role(role.name)
    resp = await bmc_wrapper.admin_user_list()
    user_names = {user["accessKey"] for user in resp.content}
    assert role.name not in user_names


async def test_role_delete_with_permissions(
    minio_provider: MinioBucketProvider, bmc_wrapper: BMCWrapper
) -> None:
    role = await minio_provider.create_role("integration_test_role")
    await minio_provider.set_role_permissions(
        role,
        [
            BucketPermission(
                bucket_name="",
                write=True,
                is_prefix=True,
            )
        ],
    )
    await minio_provider.delete_role(role.name)
    resp = await bmc_wrapper.admin_user_list()
    user_names = {user["accessKey"] for user in resp.content}
    assert role.name not in user_names


async def _test_no_access(
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


async def test_bucket_credentials_public_url(
    minio_s3: AioBaseClient, minio_sts: AioBaseClient, bmc_wrapper: BMCWrapper
) -> None:
    minio_provider = MinioBucketProvider(
        minio_s3, minio_sts, bmc_wrapper, public_url=URL("https://foo.bar")
    )
    bucket = await minio_provider.create_bucket("integration-test-bucket")
    credentials = await minio_provider.get_bucket_credentials(
        bucket.name, write=True, requester="testing"
    )
    assert credentials["endpoint_url"] == "https://foo.bar"


async def test_bucket_credentials_write_access(
    minio_provider: MinioBucketProvider,
) -> None:
    bucket = await minio_provider.create_bucket("integration-test-bucket")
    credentials = await minio_provider.get_bucket_credentials(
        bucket.name, write=True, requester="testing"
    )
    await _test_write_access(credentials, bucket)


async def test_bucket_credentials_read_access(
    minio_provider: MinioBucketProvider,
    minio_s3: AioBaseClient,
) -> None:
    bucket = await minio_provider.create_bucket("integration-test-bucket")
    credentials = await minio_provider.get_bucket_credentials(
        bucket.name, write=False, requester="testing"
    )
    await _test_read_access(minio_s3, credentials, bucket)


async def test_role_grant_bucket_write_access(
    minio_provider: MinioBucketProvider,
) -> None:
    role = await minio_provider.create_role("integration_test_role")
    bucket = await minio_provider.create_bucket("integration-test-bucket")
    await minio_provider.set_role_permissions(
        role,
        [
            BucketPermission(
                bucket_name=bucket.name,
                write=True,
            )
        ],
    )
    await _test_write_access(role.credentials, bucket)


async def test_role_grant_bucket_read_only_access(
    minio_provider: MinioBucketProvider,
    minio_s3: AioBaseClient,
) -> None:
    role = await minio_provider.create_role("integration_test_role")
    bucket = await minio_provider.create_bucket("integration-test-bucket")
    await minio_provider.set_role_permissions(
        role,
        [
            BucketPermission(
                bucket_name=bucket.name,
                write=False,
            )
        ],
    )
    await _test_read_access(minio_s3, role.credentials, bucket)


async def test_role_grant_access_second_time(
    minio_provider: MinioBucketProvider,
) -> None:
    role = await minio_provider.create_role("integration_test_role")
    bucket1 = await minio_provider.create_bucket("integration-test-bucket-1")
    await minio_provider.set_role_permissions(
        role,
        [
            BucketPermission(
                bucket_name=bucket1.name,
                write=True,
            )
        ],
    )
    await _test_write_access(role.credentials, bucket1)
    bucket2 = await minio_provider.create_bucket("integration-test-bucket-2")
    await minio_provider.set_role_permissions(
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
    await _test_write_access(role.credentials, bucket1)
    await _test_write_access(role.credentials, bucket2)


async def test_role_downgrade_access(
    minio_provider: MinioBucketProvider,
    minio_s3: AioBaseClient,
) -> None:
    role = await minio_provider.create_role("integration_test_role")
    bucket = await minio_provider.create_bucket("integration-test-bucket-1")
    await minio_provider.set_role_permissions(
        role,
        [
            BucketPermission(
                bucket_name=bucket.name,
                write=True,
            )
        ],
    )
    await _test_write_access(role.credentials, bucket)
    await minio_provider.set_role_permissions(
        role,
        [
            BucketPermission(
                bucket_name=bucket.name,
                write=False,
            ),
        ],
    )
    await _test_read_access(minio_s3, role.credentials, bucket)
    await minio_provider.set_role_permissions(
        role,
        [],
    )
    await _test_no_access(minio_s3, role.credentials, bucket)
