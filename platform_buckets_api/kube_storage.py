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

    @asyncgeneratorcontextmanager
    async def list_buckets(self) -> AsyncIterator[UserBucket]:
        for bucket in await self._kube_client.list_user_buckets():
            yield bucket
