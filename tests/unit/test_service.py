from typing import Iterable, List

import pytest

from platform_buckets_api.config import BucketsProviderType
from platform_buckets_api.permissions_service import PermissionsService
from platform_buckets_api.providers import BucketPermission
from platform_buckets_api.service import BucketsService, PersistentCredentialsService
from platform_buckets_api.storage import (
    BucketsStorage,
    CredentialsStorage,
    ExistsError,
    NotExistsError,
    UserBucket,
)
from tests.mocks import MockBucketProvider


pytestmark = pytest.mark.asyncio


class MockPermissionsService(PermissionsService):
    def __init__(self) -> None:
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

    async def get_perms_checker(self, owner: str) -> "PermissionsService.Checker":
        return self.Checker(self, owner)  # type: ignore


class TestBucketsService:
    @pytest.fixture
    def mock_permissions_service(self) -> MockPermissionsService:
        return MockPermissionsService()

    @pytest.fixture
    def mock_provider(self) -> MockBucketProvider:
        return MockBucketProvider()

    @pytest.fixture
    def service(
        self,
        in_memory_buckets_storage: BucketsStorage,
        mock_permissions_service: MockPermissionsService,
        mock_provider: MockBucketProvider,
    ) -> BucketsService:
        return BucketsService(
            storage=in_memory_buckets_storage,
            bucket_provider=mock_provider,
            permissions_service=mock_permissions_service,
        )

    async def test_bucket_create(
        self, service: BucketsService, mock_provider: MockBucketProvider
    ) -> None:
        bucket = await service.create_bucket(owner="test-user", name="test-bucket")
        assert bucket.owner == "test-user"
        assert mock_provider.created_buckets == [bucket.provider_bucket]
        assert "test-user" in bucket.provider_bucket.name
        assert "test-bucket" in bucket.provider_bucket.name

    async def test_bucket_create_duplicate(
        self, service: BucketsService, mock_provider: MockBucketProvider
    ) -> None:
        await service.create_bucket(owner="test-user", name="test-bucket")
        with pytest.raises(ExistsError):
            await service.create_bucket(owner="test-user", name="test-bucket")
        if len(mock_provider.created_buckets) == 2:
            second_bucket = mock_provider.created_buckets[1]
            assert second_bucket.name in mock_provider.deleted_buckets

    async def test_bucket_create_multiple(
        self, service: BucketsService, mock_provider: MockBucketProvider
    ) -> None:
        bucket1 = await service.create_bucket(owner="test-user", name="test-bucket-1")
        bucket2 = await service.create_bucket(owner="test-user", name="test-bucket-2")
        assert mock_provider.created_buckets == [
            bucket1.provider_bucket,
            bucket2.provider_bucket,
        ]

    async def test_bucket_import(
        self, service: BucketsService, mock_provider: MockBucketProvider
    ) -> None:
        bucket = await service.import_bucket(
            owner="test-user",
            provider_bucket_name="in-provider-name",
            provider_type=BucketsProviderType.AWS,
            credentials={"key": "value"},
            name="test-bucket",
        )
        assert bucket.name == "test-bucket"
        assert bucket.owner == "test-user"
        assert bucket.provider_bucket.name == "in-provider-name"
        assert bucket.provider_bucket.provider_type == BucketsProviderType.AWS
        assert bucket.credentials == {"key": "value"}
        assert bucket.imported

    async def test_bucket_import_get(
        self, service: BucketsService, mock_provider: MockBucketProvider
    ) -> None:
        bucket = await service.import_bucket(
            owner="test-user",
            provider_bucket_name="in-provider-name",
            provider_type=BucketsProviderType.AWS,
            credentials={"key": "value"},
            name="test-bucket",
        )
        bucket_get = await service.get_bucket(bucket.id)
        assert bucket == bucket_get

    async def test_get_bucket(
        self, service: BucketsService, mock_provider: MockBucketProvider
    ) -> None:
        bucket = await service.create_bucket(owner="test-user", name="test-bucket")
        bucket_get = await service.get_bucket(bucket.id)
        assert bucket == bucket_get

    async def test_get_bucket_by_name(
        self, service: BucketsService, mock_provider: MockBucketProvider
    ) -> None:
        bucket = await service.create_bucket(owner="test-user", name="test-bucket")
        bucket_get = await service.get_bucket_by_name(
            name="test-bucket",
            owner="test-user",
        )
        assert bucket == bucket_get

    async def test_get_bucket_list(
        self, service: BucketsService, mock_provider: MockBucketProvider
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
        self, service: BucketsService, mock_provider: MockBucketProvider
    ) -> None:
        bucket = await service.create_bucket(owner="test-user", name="test-bucket")
        await service.delete_bucket(bucket.id)
        with pytest.raises(NotExistsError):
            await service.get_bucket(bucket.id)

    async def test_set_public_state_calls_provider(
        self, service: BucketsService, mock_provider: MockBucketProvider
    ) -> None:
        bucket = await service.create_bucket(owner="test-user", name="test-bucket")
        await service.set_public_access(bucket, True)
        assert mock_provider.public_state[bucket.provider_bucket.name]

    async def test_change_public_state(
        self, service: BucketsService, mock_provider: MockBucketProvider
    ) -> None:
        bucket = await service.create_bucket(owner="test-user", name="test-bucket")
        await service.set_public_access(bucket, True)
        assert (await service.get_bucket(bucket.id)).public
        await service.set_public_access(bucket, False)
        assert not (await service.get_bucket(bucket.id)).public


class TestPersistentCredentialsService:
    @pytest.fixture
    def mock_permissions_service(self) -> MockPermissionsService:
        return MockPermissionsService()

    @pytest.fixture
    def mock_provider(self) -> MockBucketProvider:
        return MockBucketProvider()

    @pytest.fixture
    def buckets_service(
        self,
        in_memory_buckets_storage: BucketsStorage,
        mock_permissions_service: MockPermissionsService,
        mock_provider: MockBucketProvider,
    ) -> BucketsService:
        return BucketsService(
            storage=in_memory_buckets_storage,
            bucket_provider=mock_provider,
            permissions_service=mock_permissions_service,
        )

    @pytest.fixture
    async def bucket_ids(
        self,
        buckets_service: BucketsService,
    ) -> List[str]:
        return [(await buckets_service.create_bucket("test-user")).id for _ in range(3)]

    @pytest.fixture
    def service(
        self,
        in_memory_credentials_storage: CredentialsStorage,
        mock_permissions_service: MockPermissionsService,
        mock_provider: MockBucketProvider,
        buckets_service: BucketsService,
    ) -> PersistentCredentialsService:
        return PersistentCredentialsService(
            storage=in_memory_credentials_storage,
            bucket_provider=mock_provider,
            buckets_service=buckets_service,
        )

    async def test_credentials_create(
        self,
        service: PersistentCredentialsService,
        mock_provider: MockBucketProvider,
        bucket_ids: List[str],
    ) -> None:
        credentials = await service.create_credentials(
            owner="usr", name="creds", bucket_ids=bucket_ids
        )
        assert mock_provider.created_roles == [credentials.role]
        # Because role name size is limited in GCP, only short owner/name
        # can be embedded in user name
        assert "usr" in credentials.role.name
        assert "creds" in credentials.role.name

    async def test_credentials_create_duplicate(
        self,
        service: PersistentCredentialsService,
        mock_provider: MockBucketProvider,
        bucket_ids: List[str],
    ) -> None:
        await service.create_credentials(
            owner="test-user", name="test-credentials", bucket_ids=bucket_ids
        )
        with pytest.raises(ExistsError):
            await service.create_credentials(
                owner="test-user", name="test-credentials", bucket_ids=bucket_ids
            )
        if len(mock_provider.created_roles) == 2:
            second_credentials = mock_provider.created_roles[1]
            assert second_credentials.name in mock_provider.deleted_roles

    async def test_credentials_create_multiple(
        self,
        service: PersistentCredentialsService,
        mock_provider: MockBucketProvider,
        bucket_ids: List[str],
    ) -> None:
        credentials1 = await service.create_credentials(
            owner="test-user", name="test-credentials-1", bucket_ids=bucket_ids
        )
        credentials2 = await service.create_credentials(
            owner="test-user", name="test-credentials-2", bucket_ids=bucket_ids
        )
        assert mock_provider.created_roles == [
            credentials1.role,
            credentials2.role,
        ]

    async def test_get_credentials(
        self,
        service: PersistentCredentialsService,
        mock_provider: MockBucketProvider,
        bucket_ids: List[str],
    ) -> None:
        credentials = await service.create_credentials(
            owner="test-user", name="test-credentials", bucket_ids=bucket_ids
        )
        credentials_get = await service.get_credentials(credentials.id)
        assert credentials == credentials_get

    async def test_get_credentials_by_name(
        self,
        service: PersistentCredentialsService,
        mock_provider: MockBucketProvider,
        bucket_ids: List[str],
    ) -> None:
        credentials = await service.create_credentials(
            owner="test-user", name="test-credentials", bucket_ids=bucket_ids
        )
        credentials_get = await service.get_credentials_by_name(
            name="test-credentials",
            owner="test-user",
        )
        assert credentials == credentials_get

    async def test_get_credentials_list(
        self,
        service: PersistentCredentialsService,
        mock_provider: MockBucketProvider,
        bucket_ids: List[str],
    ) -> None:
        credentials1 = await service.create_credentials(
            owner="test-user", name="test-credentials1", bucket_ids=bucket_ids
        )
        credentials2 = await service.create_credentials(
            owner="test-user", name="test-credentials2", bucket_ids=bucket_ids
        )
        credentials3 = await service.create_credentials(
            owner="another-user", name="test-credentials3", bucket_ids=bucket_ids
        )
        async with service.list_user_credentials("test-user") as it:
            credentials = [credentials async for credentials in it]
        assert len(credentials) == 2
        assert credentials1 in credentials
        assert credentials2 in credentials
        assert credentials3 not in credentials

    async def test_delete_credentials(
        self,
        service: PersistentCredentialsService,
        mock_provider: MockBucketProvider,
        bucket_ids: List[str],
    ) -> None:
        credentials = await service.create_credentials(
            owner="test-user", name="test-credentials", bucket_ids=bucket_ids
        )
        await service.delete_credentials(credentials.id)
        with pytest.raises(NotExistsError):
            await service.get_credentials(credentials.id)

    async def test_credentials(
        self,
        buckets_service: BucketsService,
        service: PersistentCredentialsService,
        mock_provider: MockBucketProvider,
    ) -> None:
        bucket1 = await buckets_service.create_bucket(
            owner="test-user", name="test-bucket-1"
        )
        bucket2_1 = await buckets_service.create_bucket(
            owner="test-user2", name="test-bucket-2-1"
        )
        bucket2_2 = await buckets_service.create_bucket(
            owner="test-user2", name="test-bucket-2-2"
        )
        bucket3_1 = await buckets_service.create_bucket(
            owner="test-user3", name="test-bucket-3-1"
        )
        bucket3_2 = await buckets_service.create_bucket(
            owner="test-user3", name="test-bucket-3-2"
        )
        all_buckets = [bucket1, bucket2_1, bucket2_2, bucket3_1, bucket3_2]
        all_buckets_ids = [bucket.id for bucket in all_buckets]

        def _check_access(
            perms: Iterable[BucketPermission], bucket: UserBucket, *, write: bool
        ) -> bool:
            for perm in perms:
                if not perm.write and write:
                    continue
                if bucket.provider_bucket.name == perm.bucket_name:
                    return True
            return False

        credentials = await service.create_credentials(
            name=None, owner="test-user", bucket_ids=all_buckets_ids
        )
        perms = mock_provider.role_to_permissions[credentials.role.name]
        assert all(_check_access(perms, bucket, write=True) for bucket in all_buckets)
