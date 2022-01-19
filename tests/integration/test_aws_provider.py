from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from functools import partial

import aiobotocore.session
import pytest
from aiobotocore.client import AioBaseClient
from yarl import URL

from platform_buckets_api.providers import AWSBucketProvider
from platform_buckets_api.storage import ProviderBucket

from tests.integration.conftest import MotoConfig
from tests.integration.test_provider_base import (
    BasicBucketClient,
    ProviderTestOption,
    TestProviderBase,
    as_admin_cm,
)


async def aws_bucket_exists(s3: AioBaseClient, name: str) -> bool:
    buckets = await s3.list_buckets()
    names = [bucket["Name"] for bucket in buckets["Buckets"]]
    return name in names


async def aws_role_exists(iam: AioBaseClient, name: str) -> bool:
    users = await iam.list_users()
    user_names = {user["UserName"] for user in users["Users"]}
    return name in user_names


class AwsBasicBucketClient(BasicBucketClient):
    def __init__(self, client: AioBaseClient, bucket_name: str) -> None:
        self._client = client
        self._bucket_name = bucket_name

    @classmethod
    @asynccontextmanager
    async def create(
        cls, bucket: ProviderBucket, credentials: Mapping[str, str]
    ) -> AsyncIterator["AwsBasicBucketClient"]:
        session = aiobotocore.session.get_session()
        async with session.create_client(
            "s3",
            endpoint_url=credentials["endpoint_url"],
            region_name=credentials["region_name"],
            aws_access_key_id=credentials["access_key_id"],
            aws_secret_access_key=credentials["secret_access_key"],
            aws_session_token=credentials.get("session_token"),
        ) as users_s3_client:
            yield cls(users_s3_client, bucket.name)

    async def read_object(self, key: str) -> bytes:
        response = await self._client.get_object(Bucket=self._bucket_name, Key=key)
        async with response["Body"] as stream:
            return await stream.read()

    async def list_objects(self) -> list[str]:
        keys = []
        paginator = self._client.get_paginator("list_objects")
        async for result in paginator.paginate(Bucket=self._bucket_name):
            for c in result.get("Contents", []):
                keys.append(c["Key"])
        return keys

    async def delete_object(self, key: str) -> None:
        await self._client.delete_object(Bucket=self._bucket_name, Key=key)

    async def put_object(self, key: str, data: bytes) -> None:
        await self._client.put_object(
            Bucket=self._bucket_name,
            Key=key,
            Body=data,
        )


class TestAWSProvider(TestProviderBase):
    __test__ = True

    @pytest.fixture()
    async def provider_option(
        self,
        s3: AioBaseClient,
        iam: AioBaseClient,
        sts: AioBaseClient,
        s3_role: str,
        moto_server: MotoConfig,
    ) -> ProviderTestOption:
        return ProviderTestOption(
            type="aws",
            provider=AWSBucketProvider(s3, iam, sts, s3_role),
            bucket_exists=partial(aws_bucket_exists, s3),
            make_client=AwsBasicBucketClient.create,
            get_admin=as_admin_cm(lambda bucket: AwsBasicBucketClient(s3, bucket.name)),
            role_exists=partial(aws_role_exists, iam),
            get_public_url=lambda bucket_name, key: URL(
                s3.meta.endpoint_url + f"/{bucket_name}/{key}"
            ),
            credentials_for_imported={
                "endpoint_url": str(moto_server.url),
                "access_key_id": moto_server.admin_access_key_id,
                "secret_access_key": moto_server.admin_secret_access_key,
            },
        )
