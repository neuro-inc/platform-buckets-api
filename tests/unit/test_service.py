from typing import Iterable, List

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
        self.can_write_any = False
        self.can_read_any = False
        self.read_owned_additional: List[str] = []
        self.write_owned_additional: List[str] = []
        self.can_read_bucket_ids: List[str] = []
        self.can_write_bucket_ids: List[str] = []

    class Checker:
        def __init__(self, service: "MockPermissionsService", owner: str):
            self.service = service
            self.owner = owner

        def can_read(self, bucket: UserBucket) -> bool:
            return (
                bucket.owner == self.owner
                or bucket.id in self.service.can_read_bucket_ids
            )

        def can_write(self, bucket: UserBucket) -> bool:
            return (
                bucket.owner == self.owner
                or bucket.id in self.service.can_write_bucket_ids
            )

        def can_write_any(self) -> bool:
            return self.service.can_write_any

        def can_read_any(self) -> bool:
            return self.service.can_read_any

        def read_access_for_owner_by(self) -> List[str]:
            return [self.owner] + self.service.read_owned_additional

        def write_access_for_owner_by(self) -> List[str]:
            return [self.owner] + self.service.write_owned_additional

    async def get_perms_checker(self, owner: str) -> "PermissionsService.Checker":
        return self.Checker(self, owner)  # type: ignore


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
        assert "test-user" in bucket.provider_bucket.name
        assert "test-bucket" in bucket.provider_bucket.name

        credentials = await service.get_user_credentials("test-user")
        assert mock_provider.created_roles == [credentials.role]
        perms = mock_provider.role_to_permissions[credentials.role.id]
        assert len(perms) == 1
        perm = list(perms)[0]
        assert perm.write
        assert perm.is_prefix
        assert bucket.provider_bucket.name.startswith(perm.bucket_name)

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
        assert len(perms) == 1
        perm = list(perms)[0]
        assert perm.write
        assert perm.is_prefix
        assert bucket1.provider_bucket.name.startswith(perm.bucket_name)
        assert bucket2.provider_bucket.name.startswith(perm.bucket_name)

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

    async def test_credentials(
        self,
        service: Service,
        mock_provider: MockBucketProvider,
        mock_permissions_service: MockPermissionsService,
    ) -> None:
        bucket1 = await service.create_bucket(owner="test-user", name="test-bucket-1")
        bucket2_1 = await service.create_bucket(
            owner="test-user2", name="test-bucket-2-1"
        )
        bucket2_2 = await service.create_bucket(
            owner="test-user2", name="test-bucket-2-2"
        )
        bucket3_1 = await service.create_bucket(
            owner="test-user3", name="test-bucket-3-1"
        )
        bucket3_2 = await service.create_bucket(
            owner="test-user3", name="test-bucket-3-2"
        )
        all_buckets = [bucket1, bucket2_1, bucket2_2, bucket3_1, bucket3_2]
        user_1_buckets = [bucket1]
        user_2_buckets = [bucket2_1, bucket2_2]
        user_3_buckets = [bucket3_1, bucket3_2]

        def _check_access(
            perms: Iterable[BucketPermission], bucket: UserBucket, *, write: bool
        ) -> bool:
            for perm in perms:
                if not perm.write and write:
                    continue
                starts_with = bucket.provider_bucket.name.startswith(perm.bucket_name)
                same_name = bucket.provider_bucket.name == perm.bucket_name
                if perm.is_prefix and starts_with:
                    return True
                if same_name:
                    return True
            return False

        mock_permissions_service.can_write_any = True
        credentials = await service.get_user_credentials("test-user")
        perms = mock_provider.role_to_permissions[credentials.role.id]
        assert all(_check_access(perms, bucket, write=True) for bucket in all_buckets)

        mock_permissions_service.can_write_any = False
        mock_permissions_service.can_read_any = True
        credentials = await service.get_user_credentials("test-user")
        perms = mock_provider.role_to_permissions[credentials.role.id]
        assert all(_check_access(perms, bucket, write=False) for bucket in all_buckets)
        assert all(
            _check_access(perms, bucket, write=True) for bucket in user_1_buckets
        )
        assert all(
            not _check_access(perms, bucket, write=True) for bucket in user_2_buckets
        )
        assert all(
            not _check_access(perms, bucket, write=True) for bucket in user_3_buckets
        )

        mock_permissions_service.can_write_any = False
        mock_permissions_service.can_read_any = False
        mock_permissions_service.can_read_bucket_ids = [bucket3_1.id, bucket3_2.id]
        mock_permissions_service.can_write_bucket_ids = [bucket3_2.id]

        credentials = await service.get_user_credentials("test-user")
        perms = mock_provider.role_to_permissions[credentials.role.id]
        assert all(
            _check_access(perms, bucket, write=True) for bucket in user_1_buckets
        )
        assert _check_access(perms, bucket3_1, write=False)
        assert not _check_access(perms, bucket3_1, write=True)
        assert _check_access(perms, bucket3_2, write=True)
        assert all(
            not _check_access(perms, bucket, write=False) for bucket in user_2_buckets
        )

        mock_permissions_service.can_read_bucket_ids = []
        mock_permissions_service.can_write_bucket_ids = []
        mock_permissions_service.write_owned_additional = ["test-user2"]
        mock_permissions_service.read_owned_additional = ["test-user3"]
        credentials = await service.get_user_credentials("test-user")
        perms = mock_provider.role_to_permissions[credentials.role.id]
        print(list(perms))
        assert all(
            _check_access(perms, bucket, write=True) for bucket in user_1_buckets
        )
        assert all(
            _check_access(perms, bucket, write=True) for bucket in user_2_buckets
        )
        assert all(
            _check_access(perms, bucket, write=False) for bucket in user_3_buckets
        )
        assert all(
            not _check_access(perms, bucket, write=True) for bucket in user_3_buckets
        )
