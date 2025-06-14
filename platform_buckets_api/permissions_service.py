from apolo_kube_client.apolo import NO_ORG, normalize_name
from neuro_auth_client import AuthClient, ClientSubTreeViewRoot, Permission

from platform_buckets_api.storage import BaseBucket


class PermissionsService:
    def __init__(self, auth_client: AuthClient, cluster_name: str):
        self._auth_client = auth_client
        self._bucket_cluster_uri = f"blob://{cluster_name}"

    def get_create_bucket_perms(
        self, project_name: str, org_name: str | None
    ) -> list[Permission]:
        if org_name:
            return [
                Permission(
                    f"{self._bucket_cluster_uri}/{org_name}/{project_name}", "write"
                )
            ]
        return [Permission(f"{self._bucket_cluster_uri}/{project_name}", "write")]

    def _get_bucket_uris(self, bucket: BaseBucket) -> list[str]:
        base = self._bucket_cluster_uri
        if bucket.org_name and normalize_name(bucket.org_name) != normalize_name(
            NO_ORG
        ):
            base = f"{base}/{bucket.org_name}"
        return [
            f"{base}/{bucket.project_name}/{bucket.name}",
            f"{base}/{bucket.project_name}/{bucket.id}",
        ]

    def get_bucket_read_perms(self, bucket: BaseBucket) -> list[Permission]:
        return [Permission(uri, "read") for uri in self._get_bucket_uris(bucket)]

    def get_bucket_write_perms(self, bucket: BaseBucket) -> list[Permission]:
        return [Permission(uri, "write") for uri in self._get_bucket_uris(bucket)]

    class Checker:
        SCHEME = "blob:/"

        def __init__(self, service: "PermissionsService", tree: ClientSubTreeViewRoot):
            self._tree = tree
            self._service = service

        def can_read(self, bucket: BaseBucket) -> bool:
            return any(
                self._tree.allows(perm)
                for perm in self._service.get_bucket_read_perms(bucket)
            )

        def can_write(self, bucket: BaseBucket) -> bool:
            return any(
                self._tree.allows(perm)
                for perm in self._service.get_bucket_write_perms(bucket)
            )

    async def get_perms_checker(self, owner: str) -> "PermissionsService.Checker":
        tree = await self._auth_client.get_permissions_tree(
            owner,
            resource=self._bucket_cluster_uri,
        )
        return self.Checker(self, tree)
