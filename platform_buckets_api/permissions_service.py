from typing import List

from neuro_auth_client import AuthClient, ClientSubTreeViewRoot, Permission, User
from neuro_auth_client.client import check_action_allowed

from platform_buckets_api.storage import BaseBucket


class PermissionsService:
    def __init__(self, auth_client: AuthClient, cluster_name: str):
        self._auth_client = auth_client
        self._bucket_cluster_uri = f"blob://{cluster_name}"

    def get_create_bucket_perms(self, user: User) -> List[Permission]:
        return [Permission(f"{self._bucket_cluster_uri}/{user.name}", "write")]

    def get_bucket_read_perms(self, bucket: BaseBucket) -> List[Permission]:
        return [
            Permission(
                f"{self._bucket_cluster_uri}/{bucket.owner}/{bucket.name}", "read"
            ),
            Permission(
                f"{self._bucket_cluster_uri}/{bucket.owner}/{bucket.id}", "read"
            ),
        ]

    def get_bucket_write_perms(self, bucket: BaseBucket) -> List[Permission]:
        return [
            Permission(
                f"{self._bucket_cluster_uri}/{bucket.owner}/{bucket.name}", "write"
            ),
            Permission(
                f"{self._bucket_cluster_uri}/{bucket.owner}/{bucket.id}", "write"
            ),
        ]

    class Checker:

        SCHEME = "blob:/"

        def __init__(self, service: "PermissionsService", tree: ClientSubTreeViewRoot):
            self._tree = tree
            self._service = service

        def _has_perm(self, permission: Permission) -> bool:
            action = permission.action
            uri = permission.uri
            if not uri.startswith(self.SCHEME):
                return False
            uri = uri[len(self.SCHEME) :]  # noqa
            if not uri.startswith(self._tree.path):
                return False
            uri = uri[len(self._tree.path) :]  # noqa
            node = self._tree.sub_tree
            if check_action_allowed(node.action, action):
                return True
            parts = uri.split("/")
            try:
                for part in parts:
                    if check_action_allowed(node.action, action):
                        return True
                    node = node.children[part]
                return check_action_allowed(node.action, action)
            except KeyError:
                return False

        def can_read(self, bucket: BaseBucket) -> bool:
            return any(
                self._has_perm(perm)
                for perm in self._service.get_bucket_read_perms(bucket)
            )

        def can_write(self, bucket: BaseBucket) -> bool:
            return any(
                self._has_perm(perm)
                for perm in self._service.get_bucket_write_perms(bucket)
            )

    async def get_perms_checker(self, owner: str) -> "PermissionsService.Checker":
        tree = await self._auth_client.get_permissions_tree(
            owner,
            resource=self._bucket_cluster_uri,
        )
        return self.Checker(self, tree)
