import abc
from dataclasses import dataclass
from typing import Iterable

from platform_buckets_api.storage import ProviderBucket, ProviderRole


class ProviderError(Exception):
    pass


class RoleExistsError(ProviderError):
    pass


class ClusterNotFoundError(Exception):
    pass


@dataclass(frozen=True)
class BucketPermission:
    bucket: ProviderBucket
    write: bool
    read: bool = True


class BucketProvider(abc.ABC):
    @abc.abstractmethod
    async def create_role(self, username: str) -> ProviderRole:
        pass

    @abc.abstractmethod
    async def create_bucket(self, name: str) -> ProviderBucket:
        pass

    @abc.abstractmethod
    async def set_role_permissions(
        self, role: ProviderRole, permissions: Iterable[BucketPermission]
    ) -> None:
        pass
