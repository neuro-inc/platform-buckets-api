from collections.abc import AsyncIterator
from typing import Optional

from platform_buckets_api.kube_client import (
    KubeClient,
    ResourceExists,
    ResourceNotFound,
)
from platform_buckets_api.storage import (
    BucketsStorage,
    BucketType,
    CredentialsStorage,
    ExistsError,
    NotExistsError,
    PersistentCredentials,
    StorageError,
)
from platform_buckets_api.utils.asyncio import asyncgeneratorcontextmanager


class K8SBucketsStorage(BucketsStorage):
    def __init__(self, kube_client: KubeClient) -> None:
        self._kube_client = kube_client

    async def create_bucket(self, bucket: BucketType) -> None:
        try:
            await self._kube_client.create_user_bucket(bucket)
        except ResourceExists:
            raise ExistsError(
                f"UserBucket for {bucket.owner} with name {bucket.name} already exists"
            )

    async def get_bucket(self, id: str) -> BucketType:
        res = await self._kube_client.list_user_buckets(id=id)
        assert len(res) <= 1, f"Found multiple buckets for id = {id}"
        if len(res) == 0:
            raise NotExistsError(f"UserBucket with id {id} doesn't exists")
        return res[0]

    async def get_bucket_by_name(
        self,
        name: str,
        owner: str,
    ) -> BucketType:
        res = await self._kube_client.list_user_buckets(owner=owner, name=name)
        assert (
            len(res) <= 1
        ), f"Found multiple buckets for name = {name} and owner = {owner}"
        if len(res) == 0:
            raise NotExistsError(
                f"UserBucket for {owner} with name {name} doesn't exists"
            )
        return res[0]

    @asyncgeneratorcontextmanager
    async def list_buckets(self) -> AsyncIterator[BucketType]:
        for bucket in await self._kube_client.list_user_buckets():
            yield bucket

    async def delete_bucket(self, id: str) -> None:
        try:
            bucket = await self.get_bucket(id)
        except NotExistsError:
            return
        credentials = await self._kube_client.list_persistent_credentials()
        for credential in credentials:
            if id in credential.bucket_ids:
                raise StorageError(
                    "Cannot remove UserBucket that is mentioned "
                    f"in PersistentCredentials with id {credential.id}"
                )
        await self._kube_client.remove_user_bucket(bucket)

    async def update_bucket(self, bucket: BucketType) -> None:
        try:
            await self._kube_client.update_user_bucket(bucket)
        except ResourceNotFound:
            raise NotExistsError(f"UserBucket with id {bucket.id} doesn't exists")


class K8SCredentialsStorage(CredentialsStorage):
    def __init__(self, kube_client: KubeClient) -> None:
        self._kube_client = kube_client

    async def create_credentials(self, credentials: PersistentCredentials) -> None:
        try:
            await self._kube_client.create_persistent_credentials(credentials)
        except ResourceExists:
            raise ExistsError(
                f"PersistentCredentials for {credentials.owner} with "
                f"name {credentials.name} already exists"
            )

    async def get_credentials(self, id: str) -> PersistentCredentials:
        res = await self._kube_client.list_persistent_credentials(id=id)
        assert len(res) <= 1, f"Found multiple credentials for id = {id}"
        if len(res) == 0:
            raise NotExistsError(f"PersistentCredentials with id {id} doesn't exists")
        return res[0]

    async def get_credentials_by_name(
        self,
        name: str,
        owner: str,
    ) -> PersistentCredentials:
        res = await self._kube_client.list_persistent_credentials(
            owner=owner, name=name
        )
        assert (
            len(res) <= 1
        ), f"Found multiple credentials for name = {name} and owner = {owner}"
        if len(res) == 0:
            raise NotExistsError(
                f"PersistentCredentials with name {name} and owner = {owner}"
                f" doesn't exists"
            )
        return res[0]

    @asyncgeneratorcontextmanager
    async def list_credentials(
        self, owner: Optional[str] = None
    ) -> AsyncIterator[PersistentCredentials]:
        for credentials in await self._kube_client.list_persistent_credentials(
            owner=owner
        ):
            yield credentials

    async def delete_credentials(self, id: str) -> None:
        try:
            credentials = await self.get_credentials(id)
        except NotExistsError:
            return
        await self._kube_client.remove_persistent_credentials(credentials)

    async def update_credentials(self, credentials: PersistentCredentials) -> None:
        try:
            await self._kube_client.update_persistent_credentials(credentials)
        except ResourceNotFound:
            raise NotExistsError(
                f"PersistentCredentials with id {credentials.id} doesn't exists"
            )
