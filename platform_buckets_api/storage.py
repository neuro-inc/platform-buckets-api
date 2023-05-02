import abc
from collections.abc import AsyncIterator, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Optional, Union

from .config import BucketsProviderType
from .utils.asyncio import asyncgeneratorcontextmanager


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
    name: str
    provider_type: BucketsProviderType
    credentials: Mapping[str, str]


@dataclass(frozen=True)
class ProviderBucket:
    provider_type: BucketsProviderType
    name: str
    metadata: Optional[Mapping[str, str]] = None


@dataclass(frozen=True)
class PersistentCredentials:
    id: str
    name: Optional[str]
    owner: str
    bucket_ids: list[str]
    role: ProviderRole
    read_only: bool = False


@dataclass(frozen=True)
class BaseBucket(abc.ABC):
    id: str
    name: Optional[str]
    owner: str
    org_name: Optional[str]
    project_name: str
    created_at: datetime
    provider_bucket: ProviderBucket
    public: bool
    imported: ClassVar[bool]


@dataclass(frozen=True)
class UserBucket(BaseBucket):
    imported: ClassVar[bool] = False


@dataclass(frozen=True)
class ImportedBucket(BaseBucket):
    imported: ClassVar[bool] = True
    credentials: Mapping[str, str]


BucketType = Union[UserBucket, ImportedBucket]


class BucketsStorage(abc.ABC):
    @abc.abstractmethod
    def list_buckets(
        self, org_name: Optional[str] = None, project_name: Optional[str] = None
    ) -> AbstractAsyncContextManager[AsyncIterator[BucketType]]:
        pass

    @abc.abstractmethod
    async def get_bucket(self, id: str) -> BucketType:
        pass

    @abc.abstractmethod
    async def get_bucket_by_name(
        self, name: str, org_name: Optional[str], project_name: str
    ) -> BucketType:
        pass

    @abc.abstractmethod
    async def create_bucket(self, bucket: BucketType) -> None:
        pass

    @abc.abstractmethod
    async def delete_bucket(self, id: str) -> None:
        pass

    @abc.abstractmethod
    async def update_bucket(self, bucket: BucketType) -> None:
        pass


class CredentialsStorage(abc.ABC):
    @abc.abstractmethod
    def list_credentials(
        self, owner: Optional[str] = None
    ) -> AbstractAsyncContextManager[AsyncIterator[PersistentCredentials]]:
        pass

    @abc.abstractmethod
    async def get_credentials(self, id: str) -> PersistentCredentials:
        pass

    @abc.abstractmethod
    async def get_credentials_by_name(
        self, name: str, owner: str
    ) -> PersistentCredentials:
        pass

    @abc.abstractmethod
    async def create_credentials(self, credentials: PersistentCredentials) -> None:
        pass

    @abc.abstractmethod
    async def delete_credentials(self, id: str) -> None:
        pass

    @abc.abstractmethod
    async def update_credentials(self, credentials: PersistentCredentials) -> None:
        pass


class InMemoryBucketsStorage(BucketsStorage):
    def __init__(self) -> None:
        self._buckets: list[BucketType] = []

    @asyncgeneratorcontextmanager
    async def list_buckets(
        self, org_name: Optional[str] = None, project_name: Optional[str] = None
    ) -> AsyncIterator[BucketType]:
        for bucket in self._buckets:
            if org_name and org_name != bucket.org_name:
                continue
            if project_name and project_name != bucket.project_name:
                continue
            yield bucket

    async def create_bucket(self, bucket: BucketType) -> None:
        if bucket.name:
            try:
                await self.get_bucket_by_name(
                    bucket.name, bucket.org_name, bucket.project_name
                )
                raise ExistsError(
                    f"UserBucket for {bucket.owner} with name "
                    f"{bucket.name} already exists"
                )
            except NotExistsError:
                pass
        self._buckets.append(bucket)

    async def get_bucket(
        self,
        id: str,
    ) -> BucketType:
        for bucket in self._buckets:
            if bucket.id == id:
                return bucket
        raise NotExistsError(f"UserBucket with id {id} doesn't exist")

    async def get_bucket_by_name(
        self, name: str, org_name: Optional[str], project_name: str
    ) -> BucketType:
        for bucket in self._buckets:
            if (
                bucket.name == name
                and (not org_name or bucket.org_name == org_name)
                and (not project_name or bucket.project_name == project_name)
            ):
                return bucket
        raise NotExistsError(
            f"UserBucket with name {name}, org {org_name}, "
            f"project {project_name} doesn't exist"
        )

    async def delete_bucket(self, id: str) -> None:
        self._buckets = [bucket for bucket in self._buckets if bucket.id != id]

    async def update_bucket(self, bucket: BucketType) -> None:
        for index in range(len(self._buckets)):
            if self._buckets[index].id == bucket.id:
                self._buckets[index] = bucket
                return
        raise NotExistsError(f"UserBucket with id {bucket.id} doesn't exist")


class InMemoryCredentialsStorage(CredentialsStorage):
    def __init__(self) -> None:
        self._credentials: list[PersistentCredentials] = []

    @asyncgeneratorcontextmanager
    async def list_credentials(
        self, owner: Optional[str] = None
    ) -> AsyncIterator[PersistentCredentials]:
        for credentials in self._credentials:
            if owner is None or credentials.owner == owner:
                yield credentials

    async def create_credentials(self, credentials: PersistentCredentials) -> None:
        if credentials.name:
            try:
                await self.get_credentials_by_name(
                    owner=credentials.owner, name=credentials.name
                )
                raise ExistsError(
                    f"PersistentCredentials for {credentials.owner} with name "
                    f"{credentials.name} already exists"
                )
            except NotExistsError:
                pass
        self._credentials.append(credentials)

    async def get_credentials(
        self,
        id: str,
    ) -> PersistentCredentials:
        for credentials in self._credentials:
            if credentials.id == id:
                return credentials
        raise NotExistsError(f"PersistentCredentials with id {id} doesn't exist")

    async def get_credentials_by_name(
        self,
        name: str,
        owner: str,
    ) -> PersistentCredentials:
        for credentials in self._credentials:
            if credentials.owner == owner and credentials.name == name:
                return credentials
        raise NotExistsError(
            f"PersistentCredentials with owner = {owner} and name = {name} doesn't"
            f" exists"
        )

    async def delete_credentials(self, id: str) -> None:
        self._credentials = [
            credentials for credentials in self._credentials if credentials.id != id
        ]

    async def update_credentials(self, credentials: PersistentCredentials) -> None:
        for index in range(len(self._credentials)):
            if self._credentials[index].id == credentials.id:
                self._credentials[index] = credentials
                return
        raise NotExistsError(
            f"PersistentCredentials with id {credentials.id} doesn't exist"
        )
