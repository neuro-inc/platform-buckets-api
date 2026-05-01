from functools import partial

import pytest
from aiobotocore.client import AioBaseClient
from yarl import URL

from platform_buckets_api.providers import SeaweedFSBucketProvider
from tests.integration.conftest import MotoConfig
from tests.integration.test_aws_provider import (
    AwsBasicBucketClient,
    aws_bucket_exists,
    aws_role_exists,
)
from tests.integration.test_provider_base import (
    ProviderTestOption,
    TestProviderBase,
    as_admin_cm,
)


class TestSeaweedFSProvider(TestProviderBase):
    __test__ = True

    @pytest.fixture()
    async def provider_option(
        self,
        s3: AioBaseClient,
        iam: AioBaseClient,
        moto_server: MotoConfig,
    ) -> ProviderTestOption:
        return ProviderTestOption(
            type="seaweedfs",
            provider=SeaweedFSBucketProvider(
                s3_client=s3,
                iam_client=iam,
                region_name=moto_server.region_name,
                public_url=moto_server.url,
            ),
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
                "region_name": moto_server.region_name,
            },
        )
