from typing import Optional
from uuid import uuid4

import pytest

from platform_buckets_api.config import BucketsProviderType
from platform_buckets_api.storage import (
    ExistsError,
    InMemoryStorage,
    NotExistsError,
    ProviderBucket,
    ProviderRole,
    Storage,
    UserBucket,
    UserCredentials,
)
from platform_buckets_api.utils import utc_now


pytestmark = pytest.mark.asyncio


class TestStorage:
    @pytest.fixture()
    def storage(self, in_memory_storage: InMemoryStorage) -> Storage:
        return in_memory_storage

    def _make_credentials(self, username: str) -> UserCredentials:
        return UserCredentials(
            owner=username,
            role=ProviderRole(
                id=f"test-{username}-id",
                provider_type=BucketsProviderType.AWS,
                credentials={
                    "access_key_id": "test",
                    "access_key_secret": "secret",
                },
            ),
        )

    def _make_bucket(self, username: str, name: Optional[str]) -> UserBucket:
        return UserBucket(
            id=f"bucket-{uuid4()}",
            owner=username,
            name=name,
            created_at=utc_now(),
            provider_bucket=ProviderBucket(
                provider_type=BucketsProviderType.AWS,
                name=f"{name}--{username}",
            ),
        )

    async def test_credentials_create_get(self, storage: Storage) -> None:
        credentials = self._make_credentials("test")
        await storage.create_credentials(credentials)
        res = await storage.get_credentials(owner=credentials.owner)
        assert res == credentials

    async def test_credentials_not_exists(self, storage: Storage) -> None:
        with pytest.raises(NotExistsError):
            await storage.get_credentials(owner="anything")

    async def test_credentials_duplicate_not_allowed(self, storage: Storage) -> None:
        credentials = self._make_credentials("test")
        await storage.create_credentials(credentials)
        with pytest.raises(ExistsError):
            await storage.create_credentials(credentials)

    async def test_buckets_create_list(self, storage: Storage) -> None:
        bucket1 = self._make_bucket("user1", "test")
        bucket2 = self._make_bucket("user2", None)
        bucket3 = self._make_bucket("user2", None)
        await storage.create_bucket(bucket1)
        await storage.create_bucket(bucket2)
        await storage.create_bucket(bucket3)
        async with storage.list_buckets() as it:
            buckets = {bucket async for bucket in it}
        assert buckets == {bucket1, bucket2, bucket3}

    async def test_bucket_duplicate_not_allowed(self, storage: Storage) -> None:
        bucket1 = self._make_bucket("user", "test")
        bucket2 = self._make_bucket("user", "test")
        await storage.create_bucket(bucket1)
        with pytest.raises(ExistsError):
            await storage.create_bucket(bucket2)

    async def test_buckets_create_get(self, storage: Storage) -> None:
        bucket = self._make_bucket("user1", "test")
        await storage.create_bucket(bucket)
        bucket_get = await storage.get_bucket(bucket.id)
        assert bucket == bucket_get

    async def test_buckets_get_not_found(self, storage: Storage) -> None:
        with pytest.raises(NotExistsError):
            await storage.get_bucket("anything")

    async def test_buckets_create_get_by_name(self, storage: Storage) -> None:
        bucket1 = self._make_bucket("user1", "test-1")
        bucket2 = self._make_bucket("user1", "test-2")
        await storage.create_bucket(bucket1)
        await storage.create_bucket(bucket2)
        assert bucket1.name
        bucket_get = await storage.get_bucket_by_name(bucket1.name, bucket1.owner)
        assert bucket1 == bucket_get

        assert bucket2.name
        bucket_get = await storage.get_bucket_by_name(bucket2.name, bucket1.owner)
        assert bucket2 == bucket_get

    async def test_buckets_get_by_name_not_found(self, storage: Storage) -> None:
        with pytest.raises(NotExistsError):
            await storage.get_bucket_by_name("any", "thing")

    async def test_bucket_delete(self, storage: Storage) -> None:
        bucket = self._make_bucket("user1", "test")
        await storage.create_bucket(bucket)
        await storage.delete_bucket(bucket.id)
        with pytest.raises(NotExistsError):
            await storage.get_bucket(bucket.id)
        async with storage.list_buckets() as it:
            buckets = {bucket async for bucket in it}
        assert buckets == set()
