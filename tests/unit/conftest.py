import pytest

from platform_buckets_api.storage import InMemoryStorage


@pytest.fixture
def in_memory_storage() -> InMemoryStorage:
    return InMemoryStorage()
