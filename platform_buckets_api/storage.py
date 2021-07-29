import abc
from dataclasses import dataclass
from typing import AsyncContextManager, AsyncIterator, List, Mapping

from platform_buckets_api.config import BucketsProviderType
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
    role: ProviderRole


@dataclass(frozen=True)
class UserBucket:
    name: str
    owner: str
    provider_bucket: ProviderBucket


class Storage(abc.ABC):
    @abc.abstractmethod
    async def create_credentials(self, credentials: UserCredentials) -> None:
        pass

    @abc.abstractmethod
    async def get_credentials(self, owner: str) -> UserCredentials:
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
            await self.get_credentials(credentials.owner)
            raise ExistsError(f"UserCredentials for {credentials.owner} already exists")
        except NotExistsError:
            pass
        self._credentials.append(credentials)

    async def get_credentials(self, owner: str) -> UserCredentials:
        for cred in self._credentials:
            if cred.owner == owner:
                return cred
        raise NotExistsError(f"UserCredentials for {owner} doesn't exists")

    @asyncgeneratorcontextmanager
    async def list_buckets(self) -> AsyncIterator[UserBucket]:
        for bucket in self._buckets:
            yield bucket

    async def create_bucket(self, bucket: UserBucket) -> None:
        try:
            await self._get_bucket(owner=bucket.owner, name=bucket.name)
            raise ExistsError(
                f"UserBucket for {bucket.owner} with name {bucket.name} already exists"
            )
        except NotExistsError:
            pass
        self._buckets.append(bucket)

    async def _get_bucket(self, owner: str, name: str) -> UserBucket:
        for bucket in self._buckets:
            if bucket.owner == owner and bucket.name == name:
                return bucket
        raise NotExistsError(f"UserBucket for {owner} with name {name} doesn't exists")
