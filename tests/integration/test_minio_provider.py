from functools import partial

import pytest
from aiobotocore.client import AioBaseClient

from platform_buckets_api.providers import BMCWrapper, MinioBucketProvider
from tests.integration.test_aws_provider import AwsBasicBucketClient, aws_bucket_exists
from tests.integration.test_provider_base import ProviderTestOption, TestProviderBase


pytestmark = pytest.mark.asyncio


async def minio_role_exists(bmc_wrapper: BMCWrapper, name: str) -> bool:
    resp = await bmc_wrapper.admin_user_list()
    user_names = {user["accessKey"] for user in resp.content}
    return name in user_names


class TestMinioProvider(TestProviderBase):
    __test__ = True

    @pytest.fixture()
    async def provider_option(
        self, minio_s3: AioBaseClient, minio_sts: AioBaseClient, bmc_wrapper: BMCWrapper
    ) -> ProviderTestOption:
        return ProviderTestOption(
            type="minio",
            provider=MinioBucketProvider(minio_s3, minio_sts, bmc_wrapper),
            bucket_exists=partial(aws_bucket_exists, minio_s3),
            make_client=AwsBasicBucketClient.create,
            get_admin=lambda bucket: AwsBasicBucketClient(minio_s3, bucket.name),
            role_exists=partial(minio_role_exists, bmc_wrapper),
        )
