import pytest

from platform_buckets_api.storage import (
    BucketsProviderType,
    ExistsError,
    InMemoryStorage,
    NotExistsError,
    ProviderBucket,
    ProviderRole,
    Storage,
    UserBucket,
    UserCredentials,
)


pytestmark = pytest.mark.asyncio


class TestStorage:
    @pytest.fixture()
    def storage(self, in_memory_storage: InMemoryStorage) -> Storage:
        return in_memory_storage

    def _make_credentials(self, username: str) -> UserCredentials:
        return UserCredentials(
            owner=username,
            role=ProviderRole(
                id="test-id",
                provider_type=BucketsProviderType.AWS,
                credentials={
                    "access_key_id": "test",
                    "access_key_secret": "secret",
                },
            ),
        )

    def _make_bucket(self, username: str, name: str) -> UserBucket:
        return UserBucket(
            owner=username,
            name=name,
            provider_bucket=ProviderBucket(
                id="test-id",
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
        bucket2 = self._make_bucket("user2", "test")
        await storage.create_bucket(bucket1)
        await storage.create_bucket(bucket2)
        async with storage.list_buckets() as it:
            buckets = {bucket async for bucket in it}
        assert buckets == {bucket1, bucket2}

    async def test_bucket_duplicate_not_allowed(self, storage: Storage) -> None:
        bucket = self._make_bucket("user", "test")
        await storage.create_bucket(bucket)
        with pytest.raises(ExistsError):
            await storage.create_bucket(bucket)
