from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

import apolo_sdk
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from apolo_app_types.protocols.common.buckets import (
    Bucket,
    BucketProvider,
    CredentialsType,
    GCPBucketCredentials,
    MinioBucketCredentials,
    S3BucketCredentials,
)
from src.main import app


@pytest.fixture
def mock_apolo_client():
    """Mock apolo SDK client."""
    return AsyncMock(spec=apolo_sdk.Client)


@pytest.fixture
def mock_bucket_data():
    """Sample bucket data for testing."""
    # Create simple mock objects that have the required attributes
    bucket1 = MagicMock()
    bucket1.id = "bucket-1"
    bucket1.name = "test-bucket-1"
    bucket1.owner = "user1"
    # Mock the provider as an enum-like object with .value attribute
    bucket1.provider = MagicMock()
    bucket1.provider.value = "aws"
    bucket1.imported = False
    bucket1.project_name = "test-project"

    bucket2 = MagicMock()
    bucket2.id = "bucket-2"
    bucket2.name = "test-bucket-2"
    bucket2.owner = "user2"
    bucket2.provider = MagicMock()
    bucket2.provider.value = "minio"
    bucket2.imported = False
    bucket2.project_name = "test-project"

    bucket3 = MagicMock()
    bucket3.id = "bucket-3"
    bucket3.name = "gcp-bucket"
    bucket3.owner = "user1"
    bucket3.provider = MagicMock()
    bucket3.provider.value = "gcp"
    bucket3.imported = False
    bucket3.project_name = "test-project"

    return [bucket1, bucket2, bucket3]


@pytest.fixture
def mock_credentials_data():
    """Sample credentials data for testing."""
    # Create simple mock credential items
    cred_item1 = MagicMock()
    cred_item1.bucket_id = "bucket-1"
    cred_item1.provider = MagicMock()
    cred_item1.provider.value = "aws"
    cred_item1.credentials = {
        "bucket_name": "test-bucket-1",
        "endpoint_url": "https://s3.amazonaws.com",
        "region_name": "us-east-1",
        "access_key_id": "AKIATEST",
        "secret_access_key": "secret123",
    }

    cred_item2 = MagicMock()
    cred_item2.bucket_id = "bucket-2"
    cred_item2.provider = MagicMock()
    cred_item2.provider.value = "minio"
    cred_item2.credentials = {
        "bucket_name": "test-bucket-2",
        "endpoint_url": "https://minio.example.com",
        "region_name": "us-east-1",
        "access_key_id": "minioaccess",
        "secret_access_key": "miniosecret",
    }

    cred_item3 = MagicMock()
    cred_item3.bucket_id = "bucket-3"
    cred_item3.provider = MagicMock()
    cred_item3.provider.value = "gcp"
    cred_item3.credentials = {
        "bucket_name": "gcp-bucket",
        "key_data": '{"type": "service_account", "project_id": "test"}',
    }

    creds1 = MagicMock()
    creds1.id = "creds-1"
    creds1.owner = "user1"
    creds1.name = "s3-creds"
    creds1.read_only = False
    creds1.credentials = [cred_item1]

    creds2 = MagicMock()
    creds2.id = "creds-2"
    creds2.owner = "user2"
    creds2.name = "minio-creds"
    creds2.read_only = True
    creds2.credentials = [cred_item2]

    creds3 = MagicMock()
    creds3.id = "creds-3"
    creds3.owner = "user1"
    creds3.name = "gcp-creds"
    creds3.read_only = False
    creds3.credentials = [cred_item3]

    return [creds1, creds2, creds3]


@pytest.fixture
def expected_bucket_responses():
    """Expected bucket response data."""
    return [
        Bucket(
            id="bucket-1",
            owner="user1",
            bucket_provider=BucketProvider.AWS,
            credentials=[
                S3BucketCredentials(
                    type=CredentialsType.READ_WRITE,
                    name="test-bucket-1",
                    endpoint_url="https://s3.amazonaws.com",
                    region_name="us-east-1",
                    access_key_id="AKIATEST",
                    secret_access_key="secret123",
                )
            ],
        ),
        Bucket(
            id="bucket-2",
            owner="user2",
            bucket_provider=BucketProvider.MINIO,
            credentials=[
                MinioBucketCredentials(
                    type=CredentialsType.READ_ONLY,
                    name="test-bucket-2",
                    endpoint_url="https://minio.example.com",
                    region_name="us-east-1",
                    access_key_id="minioaccess",
                    secret_access_key="miniosecret",
                )
            ],
        ),
        Bucket(
            id="bucket-3",
            owner="user1",
            bucket_provider=BucketProvider.GCP,
            credentials=[
                GCPBucketCredentials(
                    type=CredentialsType.READ_WRITE,
                    name="gcp-bucket",
                    key_data='{"type": "service_account", "project_id": "test"}',
                )
            ],
        ),
    ]


@pytest.fixture
def mock_apolo_client_dependency(
    mock_apolo_client, mock_bucket_data, mock_credentials_data
):
    """Mock dependency for apolo client."""

    def mock_buckets_list():
        async def _inner():
            for bucket in mock_bucket_data:
                yield bucket

        return _inner()

    def mock_credentials_list():
        async def _inner():
            for cred in mock_credentials_data:
                yield cred

        return _inner()

    # Set up mocks to return fresh generators each time they're called
    mock_apolo_client.buckets.list.side_effect = mock_buckets_list
    mock_apolo_client.buckets.persistent_credentials_list.side_effect = (
        mock_credentials_list
    )

    async def get_mock_client():
        yield mock_apolo_client

    return get_mock_client

    async def get_mock_client() -> AsyncGenerator[apolo_sdk.Client, None]:
        yield mock_apolo_client

    return get_mock_client


@pytest_asyncio.fixture
async def async_client(mock_apolo_client_dependency):
    """Async test client with mocked dependencies."""
    from src.dependencies import dep_get_apolo_client

    app.dependency_overrides[dep_get_apolo_client] = mock_apolo_client_dependency

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport, base_url="http://test"
    ) as async_test_client:
        yield async_test_client

    # Clean up overrides after test
    app.dependency_overrides.clear()
