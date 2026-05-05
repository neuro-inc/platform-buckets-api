from functools import partial

import pytest
from aiobotocore.client import AioBaseClient
from yarl import URL

from platform_buckets_api.providers import SeaweedFSBucketProvider
from tests.integration.test_aws_provider import AwsBasicBucketClient, aws_bucket_exists
from tests.integration.test_provider_base import (
    ProviderTestOption,
    TestProviderBase,
    as_admin_cm,
)


async def seaweedfs_role_exists(iam: AioBaseClient, name: str) -> bool:
    try:
        users = await iam.list_users()
        user_names = {user["UserName"] for user in users.get("Users", [])}
        return name in user_names
    except Exception:
        return False


class TestSeaweedFSProvider(TestProviderBase):
    __test__ = True

    @pytest.fixture()
    async def provider_option(
        self,
        seaweedfs_s3: AioBaseClient,
        seaweedfs_iam: AioBaseClient,
        seaweedfs_sts: AioBaseClient,
        seaweedfs_server: URL,
    ) -> ProviderTestOption:
        return ProviderTestOption(
            type="seaweedfs",
            provider=SeaweedFSBucketProvider(
                s3_client=seaweedfs_s3,
                iam_client=seaweedfs_iam,
                sts_client=seaweedfs_sts,
                s3_role_arn="arn:aws:iam::123456789012:role/s3-role",
                region_name="us-east-1",
                public_url=seaweedfs_server,
            ),
            bucket_exists=partial(aws_bucket_exists, seaweedfs_s3),
            make_client=AwsBasicBucketClient.create,
            get_admin=as_admin_cm(
                lambda bucket: AwsBasicBucketClient(seaweedfs_s3, bucket.name)
            ),
            role_exists=partial(seaweedfs_role_exists, seaweedfs_iam),
            get_public_url=lambda bucket_name, key: URL(
                seaweedfs_s3.meta.endpoint_url + f"/{bucket_name}/{key}"
            ),
            credentials_for_imported={
                "endpoint_url": str(seaweedfs_server),
                "access_key_id": "root",
                "secret_access_key": "root",
                "region_name": "us-east-1",
            },
            bucket_exists_reliable=False,
            temporary_credentials_supported=False,
            persistent_credentials_supported=False,
        )
