import asyncio
import logging
import secrets
from typing import AsyncIterator, List, Optional
from uuid import uuid4

from platform_buckets_api.permissions_service import PermissionsService
from platform_buckets_api.providers import (
    BucketPermission,
    BucketProvider,
    RoleExistsError,
)
from platform_buckets_api.storage import (
    NotExistsError,
    Storage,
    UserBucket,
    UserCredentials,
)
from platform_buckets_api.utils.asyncio import asyncgeneratorcontextmanager


logger = logging.getLogger()


class Service:
    def __init__(
        self,
        storage: Storage,
        bucket_provider: BucketProvider,
        permissions_service: PermissionsService,
    ) -> None:
        self._storage = storage
        self._permissions_service = permissions_service
        self._provider = bucket_provider

    def _make_bucket_name(self, name: Optional[str], owner: str) -> str:
        if name is None:
            return f"neuro-pl-{owner}"[:45] + secrets.token_hex(6)
        return f"neuro-pl-{name}-{owner}"[:45] + secrets.token_hex(6)

    def _make_role_name(self, owner: str) -> str:
        return f"neuro-bucketuser-{owner}-" + secrets.token_hex(5)

    async def _get_user_credentials(
        self,
        owner: str,
    ) -> UserCredentials:
        try:
            return await self._storage.get_credentials(owner)
        except NotExistsError:
            try:
                role_name = self._make_role_name(owner)
                role = await self._provider.create_role(role_name)
            except RoleExistsError:
                await asyncio.sleep(1)  # Race condition, retry read from DB after delay
                return await self._get_user_credentials(owner)
            credentials = UserCredentials(
                owner=owner,
                role=role,
            )
            await self._storage.create_credentials(credentials)
            return credentials

    async def create_bucket(self, owner: str, name: Optional[str] = None) -> UserBucket:
        real_name = self._make_bucket_name(name, owner)
        provider_bucket = await self._provider.create_bucket(real_name)
        bucket = UserBucket(
            id=f"bucket-{uuid4()}",
            name=name,
            owner=owner,
            provider_bucket=provider_bucket,
        )
        try:
            await self._storage.create_bucket(bucket)
        except Exception:
            await self._provider.delete_bucket(provider_bucket.name)
            raise
        return bucket

    async def get_bucket(self, id: str) -> UserBucket:
        return await self._storage.get_bucket(id)

    async def get_bucket_by_name(self, name: str, owner: str) -> UserBucket:
        return await self._storage.get_bucket_by_name(name, owner)

    async def get_user_credentials(self, username: str) -> UserCredentials:
        credentials = await self._get_user_credentials(username)
        await self._sync_permissions(credentials)
        return credentials

    async def _sync_permissions(self, credentials: UserCredentials) -> None:

        checker = await self._permissions_service.get_perms_checker(credentials.owner)

        permissions: List[BucketPermission] = []
        async with self._storage.list_buckets() as it:
            async for bucket in it:
                if checker.can_read(bucket):
                    permissions.append(
                        BucketPermission(
                            bucket=bucket.provider_bucket,
                            write=checker.can_write(bucket),
                        )
                    )
        await self._provider.set_role_permissions(credentials.role, permissions)

    @asyncgeneratorcontextmanager
    async def get_user_buckets(self, owner: str) -> AsyncIterator[UserBucket]:
        checker = await self._permissions_service.get_perms_checker(owner)
        async with self._storage.list_buckets() as it:
            async for bucket in it:
                if checker.can_read(bucket):
                    yield bucket

    async def delete_bucket(self, bucket_id: str) -> None:
        bucket = await self.get_bucket(bucket_id)
        await self._provider.delete_bucket(bucket.provider_bucket.name)
        await self._storage.delete_bucket(bucket_id)
