import pytest

from platform_buckets_api.permissions_service import PermissionsService
from platform_buckets_api.providers import BucketPermission
from platform_buckets_api.service import Service
from platform_buckets_api.storage import (
    ExistsError,
    NotExistsError,
    Storage,
    UserBucket,
)
from tests.mocks import MockBucketProvider


pytestmark = pytest.mark.asyncio


class MockPermissionsService(PermissionsService):
    def __init__(self) -> None:
        pass

    class Checker:
        def __init__(self, owner: str):
            self.owner = owner

        def can_read(self, bucket: UserBucket) -> bool:
            return bucket.owner == self.owner

        def can_write(self, bucket: UserBucket) -> bool:
            return bucket.owner == self.owner

    async def get_perms_checker(self, owner: str) -> "PermissionsService.Checker":
        return self.Checker(owner)  # type: ignore


class TestService:
    @pytest.fixture
    def mock_permissions_service(self) -> MockPermissionsService:
        return MockPermissionsService()

    @pytest.fixture
    def mock_provider(self) -> MockBucketProvider:
        return MockBucketProvider()

    @pytest.fixture
    def service(
        self,
        in_memory_storage: Storage,
        mock_permissions_service: MockPermissionsService,
        mock_provider: MockBucketProvider,
    ) -> Service:
        return Service(
            storage=in_memory_storage,
            bucket_provider=mock_provider,
            permissions_service=mock_permissions_service,
        )

    async def test_bucket_create(
        self, service: Service, mock_provider: MockBucketProvider
    ) -> None:
        bucket = await service.create_bucket(owner="test-user", name="test-bucket")
        assert mock_provider.created_buckets == [bucket.provider_bucket]
        assert bucket.provider_bucket.name.startswith("neuro-pl-test-bucket-test-user")

        credentials = await service.get_user_credentials("test-user")
        assert mock_provider.created_roles == [credentials.role]
        perms = mock_provider.role_to_permissions[credentials.role.id]
        assert perms == {
            BucketPermission(
                bucket=bucket.provider_bucket,
                write=True,
            )
        }

    async def test_bucket_create_duplicate(
        self, service: Service, mock_provider: MockBucketProvider
    ) -> None:
        await service.create_bucket(owner="test-user", name="test-bucket")
        with pytest.raises(ExistsError):
            await service.create_bucket(owner="test-user", name="test-bucket")
        if len(mock_provider.created_buckets) == 2:
            second_bucket = mock_provider.created_buckets[1]
            assert second_bucket.name in mock_provider.deleted_buckets

    async def test_bucket_create_multiple(
        self, service: Service, mock_provider: MockBucketProvider
    ) -> None:
        bucket1 = await service.create_bucket(owner="test-user", name="test-bucket-1")
        credentials1 = await service.get_user_credentials("test-user")
        bucket2 = await service.create_bucket(owner="test-user", name="test-bucket-2")
        credentials2 = await service.get_user_credentials("test-user")
        assert credentials1 == credentials2
        assert mock_provider.created_buckets == [
            bucket1.provider_bucket,
            bucket2.provider_bucket,
        ]
        assert mock_provider.created_roles == [credentials1.role]
        perms = mock_provider.role_to_permissions[credentials1.role.id]
        assert set(perms) == {
            BucketPermission(
                bucket=bucket1.provider_bucket,
                write=True,
            ),
            BucketPermission(
                bucket=bucket2.provider_bucket,
                write=True,
            ),
        }

    async def test_get_bucket(
        self, service: Service, mock_provider: MockBucketProvider
    ) -> None:
        bucket = await service.create_bucket(owner="test-user", name="test-bucket")
        bucket_get = await service.get_bucket(bucket.id)
        assert bucket == bucket_get

    async def test_get_bucket_by_name(
        self, service: Service, mock_provider: MockBucketProvider
    ) -> None:
        bucket = await service.create_bucket(owner="test-user", name="test-bucket")
        bucket_get = await service.get_bucket_by_name(
            name="test-bucket",
            owner="test-user",
        )
        assert bucket == bucket_get

    async def test_get_bucket_list(
        self, service: Service, mock_provider: MockBucketProvider
    ) -> None:
        bucket1 = await service.create_bucket(owner="test-user", name="test-bucket1")
        bucket2 = await service.create_bucket(owner="test-user", name="test-bucket2")
        bucket3 = await service.create_bucket(owner="another-user", name="test-bucket3")
        async with service.get_user_buckets("test-user") as it:
            buckets = [bucket async for bucket in it]
        assert len(buckets) == 2
        assert bucket1 in buckets
        assert bucket2 in buckets
        assert bucket3 not in buckets

    async def test_delete_bucket(
        self, service: Service, mock_provider: MockBucketProvider
    ) -> None:
        bucket = await service.create_bucket(owner="test-user", name="test-bucket")
        await service.delete_bucket(bucket.id)
        with pytest.raises(NotExistsError):
            await service.get_bucket(bucket.id)
