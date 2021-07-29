import asyncio
import logging
from typing import List, Tuple

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
        return f"neuro--{name}--{owner}"

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

    async def create_bucket(
        self, name: str, owner: str
    ) -> Tuple[UserBucket, UserCredentials]:
        real_name = self._make_bucket_name(name, owner)
        provider_bucket = await self._provider.create_bucket(real_name)
        bucket = UserBucket(
            name=name,
            owner=owner,
            provider_bucket=provider_bucket,
        )
        await self._storage.create_bucket(bucket)
        credentials = await self._get_user_credentials(owner)
        await self._sync_permissions(credentials)
        return bucket, credentials

    async def get_user_credentials(self, username: str) -> UserCredentials:
        credentials = await self._get_user_credentials(username)
        await self._sync_permissions(credentials)
        return credentials

    async def _sync_permissions(self, credentials: UserCredentials) -> None:
        def _check_bucket_perm(
            bucket: UserBucket, tree: ClientSubTreeViewRoot, action: str
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

        tree = await self._auth_client.get_permissions_tree(
            credentials.owner,
            resource=f"blob://{self._cluster_name}",
        )
        permissions: List[BucketPermission] = []
        async with self._storage.list_buckets() as it:
            async for bucket in it:
                if _check_bucket_perm(bucket, tree, "read"):
                    permissions.append(
                        BucketPermission(
                            bucket=bucket.provider_bucket,
                            write=_check_bucket_perm(bucket, tree, "write"),
                        )
                    )
        await self._provider.set_role_permissions(credentials.role, permissions)
