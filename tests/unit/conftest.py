import pytest

from platform_buckets_api.storage import (
    InMemoryBucketsStorage,
    InMemoryCredentialsStorage,
)


@pytest.fixture
def in_memory_buckets_storage() -> InMemoryBucketsStorage:
    return InMemoryBucketsStorage()


@pytest.fixture
def in_memory_credentials_storage() -> InMemoryCredentialsStorage:
    return InMemoryCredentialsStorage()
