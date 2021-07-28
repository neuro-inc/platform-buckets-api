import asyncio
import logging
from typing import List, Optional, Tuple

from neuro_auth_client import AuthClient, ClientSubTreeViewRoot
from neuro_auth_client.client import check_action_allowed

from platform_buckets_api.providers import (
    BucketPermission,
    BucketProvider,
    BucketProviderFactory,
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
        bucket_provider_factory: BucketProviderFactory,
    ) -> None:
        self._storage = storage
        self._auth_client = auth_client
        self._bucket_provider_factory = bucket_provider_factory

    def _make_bucket_name(self, name: str, owner: str) -> str:
        return f"{name}--{owner}"

    async def _get_bucket_provider(self, cluster_name: str) -> BucketProvider:
        return await self._bucket_provider_factory.get_provider(cluster_name)

    async def _get_user_credentials(
        self,
        owner: str,
        cluster_name: str,
        provider: Optional[BucketProvider] = None,
    ) -> UserCredentials:
        try:
            return await self._storage.get_credentials(owner, cluster_name)
        except NotExistsError:
            if provider is None:
                provider = await self._get_bucket_provider(cluster_name)
            try:
                role = await provider.create_role(owner)
            except RoleExistsError:
                await asyncio.sleep(1)  # Race condition, retry read from DB after delay
                return await self._get_user_credentials(owner, cluster_name, provider)
            credentials = UserCredentials(
                owner=owner,
                cluster_name=cluster_name,
                role=role,
            )
            await self._storage.create_credentials(credentials)
            return credentials

    async def create_bucket(
        self, name: str, cluster_name: str, owner: str
    ) -> Tuple[UserBucket, UserCredentials]:
        provider = await self._get_bucket_provider(cluster_name)
        real_name = self._make_bucket_name(name, owner)
        provider_bucket = await provider.create_bucket(real_name)
        bucket = UserBucket(
            name=name,
            owner=owner,
            cluster_name=cluster_name,
            provider_bucket=provider_bucket,
        )
        await self._storage.create_bucket(bucket)
        credentials = await self._get_user_credentials(owner, cluster_name, provider)
        await self._sync_permissions(credentials, provider)
        return bucket, credentials

    async def get_user_credentials(
        self, username: str, cluster_name: str
    ) -> UserCredentials:
        provider = await self._get_bucket_provider(cluster_name)
        credentials = await self._get_user_credentials(username, cluster_name, provider)
        await self._sync_permissions(credentials, provider)
        return credentials

    async def _sync_permissions(
        self, credentials: UserCredentials, provider: BucketProvider
    ) -> None:
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
            resource=f"blob://{credentials.cluster_name}",
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
        await provider.set_role_permissions(credentials.role, permissions)
