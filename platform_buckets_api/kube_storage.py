from collections.abc import AsyncIterator

from apolo_kube_client.apolo import create_namespace
from apolo_kube_client.errors import ResourceExists, ResourceNotFound

from platform_buckets_api.kube_client import (
    KubeApi,
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
    def __init__(self, kube_api: KubeApi) -> None:
        self._kube = kube_api

    async def create_bucket(self, bucket: BucketType) -> None:
        await create_namespace(
            kube_client=self._kube._kube,
            org_name=bucket.org_name,
            project_name=bucket.project_name,
        )
        try:
            await self._kube.create_user_bucket(bucket)
        except ResourceExists:
            raise ExistsError(
                f"UserBucket for {bucket.owner} with name {bucket.name} already exists"
            )

    async def get_bucket(self, id: str) -> BucketType:
        res = await self._kube.list_user_buckets(id=id)
        assert len(res) <= 1, f"Found multiple buckets for id = {id}"
        if len(res) == 0:
            raise NotExistsError(f"UserBucket with id {id} doesn't exist")
        return res[0]

    async def get_bucket_by_name(
        self, name: str, org_name: str | None, project_name: str
    ) -> BucketType:
        res = await self._kube.list_user_buckets(
            name=name, org_name=org_name, project_name=project_name
        )
        assert len(res) <= 1, (
            f"Found multiple buckets for name = {name}, "
            f"org = {org_name}, project = {project_name}"
        )
        if len(res) == 0:
            raise NotExistsError(
                f"UserBucket with org {org_name} project {project_name}, "
                f"name {name} doesn't exist"
            )
        return res[0]

    @asyncgeneratorcontextmanager
    async def list_buckets(
        self, org_name: str | None = None, project_name: str | None = None
    ) -> AsyncIterator[BucketType]:
        for bucket in await self._kube.list_user_buckets(
            org_name=org_name, project_name=project_name
        ):
            yield bucket

    async def delete_bucket(self, id: str) -> None:
        try:
            bucket = await self.get_bucket(id)
        except NotExistsError:
            return
        credentials = await self._kube.list_persistent_credentials()
        for credential in credentials:
            if id in credential.bucket_ids:
                raise StorageError(
                    "Cannot remove UserBucket that is mentioned "
                    f"in PersistentCredentials with id {credential.id}"
                )
        await self._kube.remove_user_bucket(bucket)

    async def update_bucket(self, bucket: BucketType) -> None:
        try:
            await self._kube.update_user_bucket(bucket)
        except ResourceNotFound:
            raise NotExistsError(f"UserBucket with id {bucket.id} doesn't exist")


class K8SCredentialsStorage(CredentialsStorage):
    def __init__(self, kube_api: KubeApi) -> None:
        self._kube = kube_api

    async def create_credentials(
        self,
        credentials: PersistentCredentials,
    ) -> None:
        try:
            await self._kube.create_persistent_credentials(credentials)
        except ResourceExists:
            raise ExistsError(
                f"PersistentCredentials for {credentials.owner} with "
                f"name {credentials.name} already exists"
            )

    async def get_credentials(self, id: str) -> PersistentCredentials:
        res = await self._kube.list_persistent_credentials(id=id)
        assert len(res) <= 1, f"Found multiple credentials for id = {id}"
        if len(res) == 0:
            raise NotExistsError(f"PersistentCredentials with id {id} doesn't exist")
        return res[0]

    async def get_credentials_by_name(
        self,
        name: str,
        owner: str,
    ) -> PersistentCredentials:
        res = await self._kube.list_persistent_credentials(owner=owner, name=name)
        assert len(res) <= 1, (
            f"Found multiple credentials for name = {name} and owner = {owner}"
        )
        if len(res) == 0:
            raise NotExistsError(
                f"PersistentCredentials with name {name} and owner = {owner}"
                f" doesn't exist"
            )
        return res[0]

    @asyncgeneratorcontextmanager
    async def list_credentials(
        self, owner: str | None = None
    ) -> AsyncIterator[PersistentCredentials]:
        for credentials in await self._kube.list_persistent_credentials(owner=owner):
            yield credentials

    async def delete_credentials(self, credentials: PersistentCredentials) -> None:
        try:
            credentials = await self.get_credentials(credentials.id)
        except NotExistsError:
            return
        await self._kube.remove_persistent_credentials(credentials)

    async def update_credentials(self, credentials: PersistentCredentials) -> None:
        try:
            await self._kube.update_persistent_credentials(credentials)
        except ResourceNotFound:
            raise NotExistsError(
                f"PersistentCredentials with id {credentials.id} doesn't exist"
            )
