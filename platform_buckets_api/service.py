import asyncio
import logging
import secrets
from typing import AsyncIterator, List

from neuro_auth_client import AuthClient, ClientSubTreeViewRoot
from neuro_auth_client.client import check_action_allowed

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
        auth_client: AuthClient,
        bucket_provider: BucketProvider,
        cluster_name: str,
    ) -> None:
        self._storage = storage
        self._auth_client = auth_client
        self._provider = bucket_provider
        self._cluster_name = cluster_name

    def _make_bucket_name(self, name: str, owner: str) -> str:
        return f"neuro-pl-{name}-{owner}"[:45] + secrets.token_hex(6)

    def _make_role_name(self, owner: str) -> str:
        return f"neuro-bucketuser-{owner}"

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

    async def create_bucket(self, name: str, owner: str) -> UserBucket:
        real_name = self._make_bucket_name(name, owner)
        provider_bucket = await self._provider.create_bucket(real_name)
        bucket = UserBucket(
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

    async def get_bucket(self, name: str, owner: str) -> UserBucket:
        return await self._storage.get_bucket(name, owner)

    async def get_user_credentials(self, username: str) -> UserCredentials:
        credentials = await self._get_user_credentials(username)
        await self._sync_permissions(credentials)
        return credentials

    def _check_bucket_perm(
        self, bucket: UserBucket, tree: ClientSubTreeViewRoot, action: str
    ) -> bool:
        node = tree.sub_tree
        if check_action_allowed(node.action, action):
            return True
        parts = bucket.owner.split("/") + [bucket.name]
        try:
            for part in parts:
                if check_action_allowed(node.action, action):
                    return True
                node = node.children[part]
            return check_action_allowed(node.action, action)
        except KeyError:
            return False

    async def _sync_permissions(self, credentials: UserCredentials) -> None:
        tree = await self._auth_client.get_permissions_tree(
            credentials.owner,
            resource=f"blob://{self._cluster_name}",
        )
        permissions: List[BucketPermission] = []
        async with self._storage.list_buckets() as it:
            async for bucket in it:
                if self._check_bucket_perm(bucket, tree, "read"):
                    permissions.append(
                        BucketPermission(
                            bucket=bucket.provider_bucket,
                            write=self._check_bucket_perm(bucket, tree, "write"),
                        )
                    )
        await self._provider.set_role_permissions(credentials.role, permissions)

    @asyncgeneratorcontextmanager
    async def get_user_buckets(self, owner: str) -> AsyncIterator[UserBucket]:
        tree = await self._auth_client.get_permissions_tree(
            owner,
            resource=f"blob://{self._cluster_name}",
        )
        async with self._storage.list_buckets() as it:
            async for bucket in it:
                if self._check_bucket_perm(bucket, tree, "read"):
                    yield bucket
