import datetime
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import botocore.exceptions
from yarl import URL

from platform_buckets_api.config import BucketsProviderType
from platform_buckets_api.providers import BucketPermission, SeaweedFSBucketProvider
from platform_buckets_api.storage import ProviderBucket


def _client(endpoint_url: str = "http://seaweedfs:9000") -> MagicMock:
    client = MagicMock()
    client.meta.endpoint_url = endpoint_url
    client.meta.region_name = "us-east-1"
    client.head_bucket = AsyncMock()
    client.create_bucket = AsyncMock()
    client.get_federation_token = AsyncMock()
    client.create_user = AsyncMock()
    client.create_access_key = AsyncMock()
    client.put_user_policy = AsyncMock()
    client.generate_presigned_url = AsyncMock()
    client.exceptions.BucketAlreadyExists = type(
        "BucketAlreadyExists", (Exception,), {}
    )
    client.exceptions.EntityAlreadyExistsException = type(
        "EntityAlreadyExistsException", (Exception,), {}
    )
    return client


def _provider(
    *,
    s3: MagicMock | None = None,
    iam: MagicMock | None = None,
    sts: MagicMock | None = None,
    public_s3: MagicMock | None = None,
) -> tuple[SeaweedFSBucketProvider, MagicMock, MagicMock, MagicMock]:
    s3 = s3 or _client()
    iam = iam or _client()
    sts = sts or _client()
    provider = SeaweedFSBucketProvider(
        s3_client=s3,
        iam_client=iam,
        sts_client=sts,
        public_url=URL("https://s3.example.com"),
        public_s3_client=public_s3,
    )
    return provider, s3, iam, sts


async def test_create_bucket_does_not_send_acl() -> None:
    provider, s3, _, _ = _provider()
    s3.head_bucket.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "404", "Message": "Not Found"}}, "HeadBucket"
    )

    bucket = await provider.create_bucket("test-bucket")

    assert bucket == ProviderBucket(
        name="test-bucket", provider_type=BucketsProviderType.SEAWEEDFS
    )
    s3.create_bucket.assert_awaited_once_with(Bucket="test-bucket")


async def test_get_bucket_credentials_uses_federation_token() -> None:
    provider, _, _, sts = _provider()
    expiration = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    sts.get_federation_token.return_value = {
        "Credentials": {
            "AccessKeyId": "temporary-access-key",
            "SecretAccessKey": "temporary-secret-key",
            "SessionToken": "temporary-session-token",
            "Expiration": expiration,
        }
    }
    bucket = ProviderBucket(
        name="test-bucket", provider_type=BucketsProviderType.SEAWEEDFS
    )

    credentials = await provider.get_bucket_credentials(
        bucket, write=False, requester="test-user"
    )

    assert credentials == {
        "region_name": "us-east-1",
        "endpoint_url": "https://s3.example.com",
        "access_key_id": "temporary-access-key",
        "secret_access_key": "temporary-secret-key",
        "session_token": "temporary-session-token",
        "expiration": expiration.isoformat(),
    }
    kwargs: dict[str, Any] = sts.get_federation_token.await_args.kwargs
    assert kwargs["Name"].startswith("test-bucket-test-user")
    assert kwargs["DurationSeconds"] == 3600
    assert json.loads(kwargs["Policy"])["Statement"] == [
        {
            "Effect": "Allow",
            "Action": ["s3:ListBucket"],
            "Resource": ["arn:aws:s3:::test-bucket"],
        },
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": ["arn:aws:s3:::test-bucket/*"],
        },
    ]


async def test_signed_url_uses_public_s3_client() -> None:
    public_s3 = _client("https://public.s3.example.com")
    public_s3.generate_presigned_url.return_value = (
        "https://public.s3.example.com/test-bucket/test-key?Signature=test"
    )
    provider, internal_s3, _, _ = _provider(public_s3=public_s3)
    bucket = ProviderBucket(
        name="test-bucket", provider_type=BucketsProviderType.SEAWEEDFS
    )

    url = await provider.sign_url_for_blob(bucket, "test-key")

    assert url.host == "public.s3.example.com"
    public_s3.generate_presigned_url.assert_awaited_once_with(
        ClientMethod="get_object",
        Params={"Bucket": "test-bucket", "Key": "test-key"},
        ExpiresIn=3600,
    )
    internal_s3.generate_presigned_url.assert_not_awaited()


async def test_create_role_uses_embedded_iam_without_permissions_boundary() -> None:
    provider, _, iam, _ = _provider()
    iam.create_access_key.return_value = {
        "AccessKey": {
            "AccessKeyId": "persistent-access-key",
            "SecretAccessKey": "persistent-secret-key",
        }
    }

    role = await provider.create_role(
        "test-user", [BucketPermission(bucket_name="test-bucket", write=True)]
    )

    iam.create_user.assert_awaited_once_with(UserName="test-user")
    iam.put_user_policy.assert_awaited_once()
    assert role.provider_type == BucketsProviderType.SEAWEEDFS
    assert role.credentials == {
        "region_name": "us-east-1",
        "endpoint_url": "https://s3.example.com",
        "access_key_id": "persistent-access-key",
        "secret_access_key": "persistent-secret-key",
    }
