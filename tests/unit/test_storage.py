from dataclasses import replace
from typing import Optional
from uuid import uuid4

import pytest

from platform_buckets_api.config import BucketsProviderType
from platform_buckets_api.storage import (
    BucketsStorage,
    CredentialsStorage,
    ExistsError,
    ImportedBucket,
    InMemoryBucketsStorage,
    InMemoryCredentialsStorage,
    NotExistsError,
    PersistentCredentials,
    ProviderBucket,
    ProviderRole,
    UserBucket,
)
from platform_buckets_api.utils import utc_now

pytestmark = pytest.mark.asyncio


class TestCredentialsStorage:
    @pytest.fixture()
    def storage(
        self, in_memory_credentials_storage: InMemoryCredentialsStorage
    ) -> CredentialsStorage:
        return in_memory_credentials_storage

    def _make_credentials(
        self, owner: str, name: Optional[str] = None, read_only: bool = False
    ) -> PersistentCredentials:
        return PersistentCredentials(
            id=f"credentials-{uuid4()}",
            name=name,
            owner=owner,
            role=ProviderRole(
                name=f"test-{owner}-role",
                provider_type=BucketsProviderType.AWS,
                credentials={
                    "access_key_id": "test",
                    "access_key_secret": "secret",
                },
            ),
            bucket_ids=["1", "2", "3"],
            read_only=read_only,
        )

    async def test_credentials_create_list(self, storage: CredentialsStorage) -> None:
        credentials1 = self._make_credentials("user1", "test")
        credentials2 = self._make_credentials("user2", None)
        credentials3 = self._make_credentials("user2", None, read_only=True)
        await storage.create_credentials(credentials1)
        await storage.create_credentials(credentials2)
        await storage.create_credentials(credentials3)
        async with storage.list_credentials() as it:
            credentials = [credentials async for credentials in it]
        assert len(credentials) == 3
        assert credentials1 in credentials
        assert credentials2 in credentials
        assert credentials3 in credentials

    async def test_credentials_duplicate_not_allowed(
        self, storage: CredentialsStorage
    ) -> None:
        credentials1 = self._make_credentials("user", "test")
        credentials2 = self._make_credentials("user", "test")
        await storage.create_credentials(credentials1)
        with pytest.raises(ExistsError):
            await storage.create_credentials(credentials2)

    async def test_credentials_create_get(self, storage: CredentialsStorage) -> None:
        credentials = self._make_credentials("user1", "test")
        await storage.create_credentials(credentials)
        credentials_get = await storage.get_credentials(credentials.id)
        assert credentials == credentials_get

    async def test_credentials_get_not_found(self, storage: CredentialsStorage) -> None:
        with pytest.raises(NotExistsError):
            await storage.get_credentials("anything")

    async def test_credentials_create_get_by_name(
        self, storage: CredentialsStorage
    ) -> None:
        credentials1 = self._make_credentials("user1", "test-1")
        credentials2 = self._make_credentials("user1", "test-2")
        await storage.create_credentials(credentials1)
        await storage.create_credentials(credentials2)
        assert credentials1.name
        credentials_get = await storage.get_credentials_by_name(
            credentials1.name, credentials1.owner
        )
        assert credentials1 == credentials_get

        assert credentials2.name
        credentials_get = await storage.get_credentials_by_name(
            credentials2.name, credentials1.owner
        )
        assert credentials2 == credentials_get

    async def test_credentials_get_by_name_not_found(
        self, storage: CredentialsStorage
    ) -> None:
        with pytest.raises(NotExistsError):
            await storage.get_credentials_by_name("any", "thing")

    async def test_credentials_delete(self, storage: CredentialsStorage) -> None:
        credentials = self._make_credentials("user1", "test")
        await storage.create_credentials(credentials)
        await storage.delete_credentials(credentials.id)
        with pytest.raises(NotExistsError):
            await storage.get_credentials(credentials.id)
        async with storage.list_credentials() as it:
            credentials_all = [credentials async for credentials in it]
        assert credentials_all == []


class TestBucketsStorage:
    @pytest.fixture()
    def storage(
        self, in_memory_buckets_storage: InMemoryBucketsStorage
    ) -> BucketsStorage:
        return in_memory_buckets_storage

    def _make_bucket(
        self,
        username: str,
        name: Optional[str],
        public: bool = False,
        with_meta: bool = True,
    ) -> UserBucket:
        return UserBucket(
            id=f"bucket-{uuid4()}",
            owner=username,
            name=name,
            org_name=None,
            created_at=utc_now(),
            provider_bucket=ProviderBucket(
                provider_type=BucketsProviderType.AWS,
                name=f"{name}--{username}",
                metadata={"key": "value"} if with_meta else None,
            ),
            public=public,
        )

    def _make_bucket_with_org(
        self,
        username: str,
        name: Optional[str],
        public: bool = False,
        with_meta: bool = True,
    ) -> UserBucket:
        return UserBucket(
            id=f"bucket-{uuid4()}",
            owner=username,
            name=name,
            org_name="test-org",
            created_at=utc_now(),
            provider_bucket=ProviderBucket(
                provider_type=BucketsProviderType.AWS,
                name=f"{name}--{username}",
                metadata={"key": "value"} if with_meta else None,
            ),
            public=public,
        )

    def _make_imported_bucket(
        self,
        username: str,
        name: Optional[str],
        public: bool = False,
    ) -> ImportedBucket:
        return ImportedBucket(
            id=f"bucket-{uuid4()}",
            owner=username,
            name=name,
            org_name=None,
            created_at=utc_now(),
            provider_bucket=ProviderBucket(
                provider_type=BucketsProviderType.AWS,
                name=f"{name}--{username}",
            ),
            credentials={"key": "value"},
            public=public,
        )

    async def test_buckets_create_list(self, storage: BucketsStorage) -> None:
        bucket1 = self._make_bucket("user1", "test", with_meta=False)
        bucket2 = self._make_bucket("user2", None)
        bucket3 = self._make_bucket("user2", None, True)
        bucket4 = self._make_imported_bucket("user2", None)
        await storage.create_bucket(bucket1)
        await storage.create_bucket(bucket2)
        await storage.create_bucket(bucket3)
        await storage.create_bucket(bucket4)
        async with storage.list_buckets() as it:
            buckets = [bucket async for bucket in it]
        assert len(buckets) == 4
        assert all(bucket in buckets for bucket in [bucket1, bucket2, bucket3, bucket4])

    async def test_bucket_duplicate_not_allowed(self, storage: BucketsStorage) -> None:
        bucket1 = self._make_bucket("user", "test")
        bucket2 = self._make_bucket("user", "test")
        await storage.create_bucket(bucket1)
        with pytest.raises(ExistsError):
            await storage.create_bucket(bucket2)

    async def test_buckets_create_get(self, storage: BucketsStorage) -> None:
        bucket = self._make_bucket("user1", "test")
        await storage.create_bucket(bucket)
        bucket_get = await storage.get_bucket(bucket.id)
        assert bucket == bucket_get

    async def test_buckets_create_get_with_org(self, storage: BucketsStorage) -> None:
        bucket = self._make_bucket_with_org("user1", "test")
        await storage.create_bucket(bucket)
        bucket_get = await storage.get_bucket(bucket.id)
        assert bucket == bucket_get

    async def test_buckets_get_not_found(self, storage: BucketsStorage) -> None:
        with pytest.raises(NotExistsError):
            await storage.get_bucket("anything")

    async def test_buckets_create_get_by_name(self, storage: BucketsStorage) -> None:
        bucket1 = self._make_bucket("user1", "test-1")
        bucket2 = self._make_imported_bucket("user1", "test-2")
        await storage.create_bucket(bucket1)
        await storage.create_bucket(bucket2)
        assert bucket1.name
        bucket_get = await storage.get_bucket_by_name(bucket1.name, bucket1.owner)
        assert bucket1 == bucket_get

        assert bucket2.name
        bucket_get = await storage.get_bucket_by_name(bucket2.name, bucket1.owner)
        assert bucket2 == bucket_get

    async def test_buckets_get_by_name_not_found(self, storage: BucketsStorage) -> None:
        with pytest.raises(NotExistsError):
            await storage.get_bucket_by_name("any", "thing")

    async def test_bucket_delete(self, storage: BucketsStorage) -> None:
        bucket = self._make_bucket("user1", "test")
        await storage.create_bucket(bucket)
        await storage.delete_bucket(bucket.id)
        with pytest.raises(NotExistsError):
            await storage.get_bucket(bucket.id)
        async with storage.list_buckets() as it:
            buckets = {bucket async for bucket in it}
        assert buckets == set()

    async def test_bucket_update(self, storage: BucketsStorage) -> None:
        bucket1 = self._make_bucket("user1", "test1", public=False)
        bucket2 = self._make_bucket("user1", "test2", public=False)
        await storage.create_bucket(bucket1)
        await storage.create_bucket(bucket2)
        bucket1 = replace(bucket1, public=True)
        await storage.update_bucket(bucket1)
        bucket_get = await storage.get_bucket(bucket1.id)
        assert bucket1 == bucket_get
        bucket_get = await storage.get_bucket(bucket2.id)
        assert bucket2 == bucket_get
