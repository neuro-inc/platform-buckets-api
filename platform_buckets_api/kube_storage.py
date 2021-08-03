from typing import AsyncIterator

from platform_buckets_api.kube_client import KubeClient, ResourceExists
from platform_buckets_api.storage import (
    ExistsError,
    NotExistsError,
    Storage,
    UserBucket,
    UserCredentials,
)
from platform_buckets_api.utils.asyncio import asyncgeneratorcontextmanager


class K8SStorage(Storage):
    def __init__(self, kube_client: KubeClient) -> None:
        self._kube_client = kube_client

    async def create_credentials(self, credentials: UserCredentials) -> None:
        try:
            await self._kube_client.create_user_bucket_credential(credentials)
        except ResourceExists:
            raise ExistsError(f"UserCredentials for {credentials.owner} already exists")

    async def get_credentials(self, owner: str) -> UserCredentials:
        res = await self._kube_client.list_user_bucket_credentials(owner=owner)
        assert len(res) <= 1, "Found multiple credentials for single user"
        if len(res) == 0:
            raise NotExistsError(f"UserCredentials for {owner} doesn't exists")
        return res[0]

    async def create_bucket(self, bucket: UserBucket) -> None:
        try:
            await self._kube_client.create_user_bucket(bucket)
        except ResourceExists:
            raise ExistsError(
                f"UserBucket for {bucket.owner} with name {bucket.name} already exists"
            )

    async def get_bucket(self, id: str) -> UserBucket:
        res = await self._kube_client.list_user_buckets(id=id)
        assert len(res) <= 1, f"Found multiple buckets for id = {id}"
        if len(res) == 0:
            raise NotExistsError(f"UserBucket with id {id} doesn't exists")
        return res[0]

    async def get_bucket_by_name(
        self,
        name: str,
        owner: str,
    ) -> UserBucket:
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
    async def list_buckets(self) -> AsyncIterator[UserBucket]:
        for bucket in await self._kube_client.list_user_buckets():
            yield bucket

    async def delete_bucket(self, id: str) -> None:
        try:
            bucket = await self.get_bucket(id)
        except NotExistsError:
            return
        await self._kube_client.remove_user_bucket(bucket)
