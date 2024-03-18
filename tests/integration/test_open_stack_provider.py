from collections.abc import AsyncIterator, Mapping
from functools import partial
from typing import Any

import aiobotocore.session
import pytest
from aiobotocore.client import AioBaseClient
from yarl import URL

from platform_buckets_api.providers import OpenStackBucketProvider, OpenStackStorageApi
from tests.integration.test_aws_provider import AwsBasicBucketClient
from tests.integration.test_provider_base import (
    BUCKET_NAME_PREFIX,
    ROLE_NAME_PREFIX,
    ProviderTestOption,
    TestProviderBase,
    as_admin_cm,
)


@pytest.fixture()
async def open_stack_config() -> Mapping[str, Any]:
    return {
        "account_id": "167509",
        "password": "*Y|EjRb8nB",
        "url": URL("https://api.selcdn.ru"),
        "public_url": URL("https://api.selcdn.ru/v1/SEL_167509"),
        "region_name": "ru-1",
        "s3_url": URL("https://s3.selcdn.ru"),
    }


@pytest.fixture()
async def open_stack_s3(
    open_stack_config: Mapping[str, Any]
) -> AsyncIterator[AioBaseClient]:
    session = aiobotocore.session.get_session()
    async with session.create_client(
        "s3",
        endpoint_url=str(open_stack_config["s3_url"]),
        region_name=open_stack_config["region_name"],
        aws_access_key_id=open_stack_config["account_id"],
        aws_secret_access_key=open_stack_config["password"],
    ) as s3:
        yield s3


@pytest.fixture()
async def open_stack_api(
    open_stack_s3: AioBaseClient, open_stack_config: Mapping[str, Any]
) -> AsyncIterator[OpenStackStorageApi]:
    async def _cleanup_buckets(api: OpenStackStorageApi) -> None:
        for bucket_name in await api.list_containers():
            if bucket_name.startswith(BUCKET_NAME_PREFIX):
                for obj in (
                    await open_stack_s3.list_objects_v2(Bucket=bucket_name)
                ).get("Contents", []):
                    obj_key = obj["Key"]
                    await open_stack_s3.delete_object(Bucket=bucket_name, Key=obj_key)
                await api.delete_container(bucket_name)

    async def _cleanup_users(api: OpenStackStorageApi) -> None:
        for user_name in await api.list_users():
            if user_name.startswith(BUCKET_NAME_PREFIX) or user_name.startswith(
                ROLE_NAME_PREFIX
            ):
                await api.delete_user(user_name)

    async with OpenStackStorageApi(
        account_id=open_stack_config["account_id"],
        password=open_stack_config["password"],
        url=open_stack_config["url"],
    ) as api:
        await _cleanup_users(api)
        await _cleanup_buckets(api)
        yield api
        await _cleanup_users(api)
        await _cleanup_buckets(api)


async def open_stack_bucket_exists(api: OpenStackStorageApi, name: str) -> bool:
    names = await api.list_containers()
    return name in names


async def open_stack_role_exists(api: OpenStackStorageApi, name: str) -> bool:
    user_names = await api.list_users()
    return name in user_names


@pytest.mark.skip("Disabled as we have no env to run tests")
class TestOpenStackProvider(TestProviderBase):
    __test__ = True

    @pytest.fixture()
    async def provider_option(
        self,
        open_stack_s3: AioBaseClient,
        open_stack_api: OpenStackStorageApi,
        open_stack_config: Mapping[str, Any],
    ) -> ProviderTestOption:
        return ProviderTestOption(
            type="open_stack",
            provider=OpenStackBucketProvider(
                open_stack_api,
                region_name=open_stack_config["region_name"],
                s3_url=open_stack_config["s3_url"],
            ),
            bucket_exists=partial(open_stack_bucket_exists, open_stack_api),
            make_client=AwsBasicBucketClient.create,
            get_admin=as_admin_cm(
                lambda bucket: AwsBasicBucketClient(open_stack_s3, bucket.name)
            ),
            role_exists=partial(open_stack_role_exists, open_stack_api),
            get_public_url=lambda bucket_name, key: open_stack_config["public_url"]
            / bucket_name
            / key,
            credentials_for_imported={},
        )
