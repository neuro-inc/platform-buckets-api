import abc
import enum
from dataclasses import dataclass
from typing import AsyncContextManager, AsyncIterator, List, Mapping

from platform_buckets_api.utils.asyncio import asyncgeneratorcontextmanager


class StorageError(Exception):
    pass


class TransactionError(StorageError):
    pass


class NotExistsError(StorageError):
    pass


class ExistsError(StorageError):
    pass


class UniquenessError(StorageError):
    pass


class BucketsProviderType(str, enum.Enum):
    AWS = "aws"


@dataclass(frozen=True)
class ProviderRole:
    id: str
    provider_type: BucketsProviderType
    credentials: Mapping[str, str]


@dataclass(frozen=True)
class ProviderBucket:
    id: str
    provider_type: BucketsProviderType
    name: str


@dataclass(frozen=True)
class UserCredentials:
    owner: str
    cluster_name: str
    role: ProviderRole


@dataclass(frozen=True)
class UserBucket:
    name: str
    owner: str
    cluster_name: str
    provider_bucket: ProviderBucket


class Storage(abc.ABC):
    @abc.abstractmethod
    async def create_credentials(self, credentials: UserCredentials) -> None:
        pass

    @abc.abstractmethod
    async def get_credentials(self, owner: str, cluster_name: str) -> UserCredentials:
        pass

    @abc.abstractmethod
    def list_buckets(self) -> AsyncContextManager[AsyncIterator[UserBucket]]:
        pass

    @abc.abstractmethod
    async def create_bucket(self, bucket: UserBucket) -> None:
        pass


class InMemoryStorage(Storage):
    def __init__(self) -> None:
        self._credentials: List[UserCredentials] = []
        self._buckets: List[UserBucket] = []

    async def create_credentials(self, credentials: UserCredentials) -> None:
        try:
            await self.get_credentials(credentials.owner, credentials.cluster_name)
            raise ExistsError(
                f"UserCredentials for {credentials.owner} in "
                f"cluster {credentials.cluster_name} already exists"
            )
        except NotExistsError:
            pass
        self._credentials.append(credentials)

    async def get_credentials(self, owner: str, cluster_name: str) -> UserCredentials:
        for cred in self._credentials:
            if cred.owner == owner and cred.cluster_name == cluster_name:
                return cred
        raise NotExistsError(
            f"UserCredentials for {owner} in cluster {cluster_name} doesn't exists"
        )

    @asyncgeneratorcontextmanager
    async def list_buckets(self) -> AsyncIterator[UserBucket]:
        for bucket in self._buckets:
            yield bucket

    async def create_bucket(self, bucket: UserBucket) -> None:
        try:
            await self._get_bucket(
                owner=bucket.owner, cluster_name=bucket.cluster_name, name=bucket.name
            )
            raise ExistsError(
                f"UserBucket for {bucket.owner} in cluster "
                f"{bucket.cluster_name} with name {bucket.name} already exists"
            )
        except NotExistsError:
            pass
        self._buckets.append(bucket)

    async def _get_bucket(self, owner: str, cluster_name: str, name: str) -> UserBucket:
        for bucket in self._buckets:
            if (
                bucket.owner == owner
                and bucket.cluster_name == cluster_name
                and bucket.name == name
            ):
                return bucket
        raise NotExistsError(
            f"UserBucket for {owner} in cluster {cluster_name} with name"
            f" {name} doesn't exists"
        )
