from typing import Dict, Iterable, List, Set

from platform_buckets_api.config import BucketsProviderType
from platform_buckets_api.providers import BucketPermission, BucketProvider
from platform_buckets_api.storage import ProviderBucket, ProviderRole


class MockBucketProvider(BucketProvider):
    def __init__(self) -> None:
        self.created_roles: List[ProviderRole] = []
        self.created_buckets: List[ProviderBucket] = []
        self.deleted_buckets: List[str] = []
        self.role_to_permissions: Dict[str, Set[BucketPermission]] = {}

    async def create_role(self, username: str) -> ProviderRole:
        role = ProviderRole(
            id=f"role-{len(self.created_roles) + 1}",
            provider_type=BucketsProviderType.AWS,
            credentials={"token": "value"},
        )
        self.created_roles.append(role)
        return role

    async def create_bucket(self, name: str) -> ProviderBucket:
        bucket = ProviderBucket(
            id=f"role-{len(self.created_buckets) + 1}",
            provider_type=BucketsProviderType.AWS,
            name=name,
        )
        self.created_buckets.append(bucket)
        return bucket

    async def delete_bucket(self, name: str) -> None:
        self.deleted_buckets.append(name)

    async def set_role_permissions(
        self, role: ProviderRole, permissions: Iterable[BucketPermission]
    ) -> None:
        self.role_to_permissions[role.id] = set(permissions)
