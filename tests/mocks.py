from typing import Dict, Iterable, List, Mapping, Set

from yarl import URL

from platform_buckets_api.config import BucketsProviderType
from platform_buckets_api.providers import BucketPermission, BucketProvider
from platform_buckets_api.storage import ProviderBucket, ProviderRole


class MockBucketProvider(BucketProvider):
    def __init__(self) -> None:
        self.created_roles: List[ProviderRole] = []
        self.deleted_roles: List[str] = []
        self.created_buckets: List[ProviderBucket] = []
        self.deleted_buckets: List[str] = []
        self.role_to_permissions: Dict[str, Set[BucketPermission]] = {}

    async def create_bucket(self, name: str) -> ProviderBucket:
        bucket = ProviderBucket(
            provider_type=BucketsProviderType.AWS,
            name=name,
        )
        self.created_buckets.append(bucket)
        return bucket

    async def delete_bucket(self, name: str) -> None:
        self.deleted_buckets.append(name)

    async def get_bucket_credentials(
        self, name: str, write: bool, requester: str
    ) -> Mapping[str, str]:
        return {"token": "value"}

    async def create_role(
        self, username: str, initial_permissions: Iterable[BucketPermission]
    ) -> ProviderRole:
        role = ProviderRole(
            name=username,
            provider_type=BucketsProviderType.AWS,
            credentials={"token": "value"},
        )
        self.created_roles.append(role)
        await self.set_role_permissions(role, initial_permissions)
        return role

    async def delete_role(self, role: ProviderRole) -> None:
        self.deleted_roles.append(role.name)

    async def set_role_permissions(
        self, role: ProviderRole, permissions: Iterable[BucketPermission]
    ) -> None:
        self.role_to_permissions[role.name] = set(permissions)

    async def sign_url_for_blob(
        self, bucket_name: str, key: str, expires_in_sec: int = 3600
    ) -> URL:
        raise NotImplementedError
