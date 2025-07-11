from dataclasses import replace

import pytest
from neuro_auth_client import (
    AuthClient,
    ClientAccessSubTreeView,
    ClientSubTreeViewRoot,
    Permission,
    User,
)

from platform_buckets_api.permissions_service import PermissionsService
from platform_buckets_api.storage import UserBucket
from platform_buckets_api.utils import utc_now


class MockAuthClient(AuthClient):
    def __init__(self) -> None:
        self.perm_tree_to_return = ClientSubTreeViewRoot(
            scheme="blob",
            path="",
            sub_tree=ClientAccessSubTreeView(
                action="read",
                children={},
            ),
        )

    async def get_permissions_tree(
        self, name: str, resource: str, depth: int | None = None
    ) -> ClientSubTreeViewRoot:
        return self.perm_tree_to_return


class TestPermissionsService:
    @pytest.fixture
    def cluster_name(self) -> str:
        return "test-cluster"

    @pytest.fixture
    def mock_auth_client(self, cluster_name: str) -> MockAuthClient:
        return MockAuthClient()

    @pytest.fixture
    def service(
        self,
        mock_auth_client: MockAuthClient,
        cluster_name: str,
    ) -> PermissionsService:
        return PermissionsService(
            auth_client=mock_auth_client,
            cluster_name=cluster_name,
        )

    @pytest.fixture
    def fake_user(
        self,
    ) -> User:
        return User(
            name="test-user",
        )

    @pytest.fixture
    def fake_bucket(
        self,
    ) -> UserBucket:
        return UserBucket(
            id="id",
            name="test-bucket",
            owner="test-user",
            project_name="test-project",
            org_name="no-org",
            created_at=utc_now(),
            provider_bucket=None,  # type: ignore
            public=False,
        )

    @pytest.fixture
    def fake_bucket_with_org(
        self,
    ) -> UserBucket:
        return UserBucket(
            id="id",
            name="test-bucket",
            owner="test-user",
            org_name="test-org",
            project_name="test-project",
            created_at=utc_now(),
            provider_bucket=None,  # type: ignore
            public=False,
        )

    def test_create_permissions(
        self, cluster_name: str, service: PermissionsService
    ) -> None:
        perms = service.get_create_bucket_perms("test-project", org_name=None)
        assert len(perms) == 1
        assert perms[0].uri == f"blob://{cluster_name}/test-project"
        assert perms[0].action == "write"

    def test_create_permissions_with_org(
        self, cluster_name: str, service: PermissionsService
    ) -> None:
        perms = service.get_create_bucket_perms("test-project", org_name="test-org")
        assert len(perms) == 1
        assert perms[0].uri == f"blob://{cluster_name}/test-org/test-project"
        assert perms[0].action == "write"

    def test_read_permissions(
        self, cluster_name: str, service: PermissionsService, fake_bucket: UserBucket
    ) -> None:
        perms = service.get_bucket_read_perms(fake_bucket)
        assert len(perms) == 2
        assert (
            Permission(
                uri=f"blob://{cluster_name}/{fake_bucket.project_name}/"
                f"{fake_bucket.id}",
                action="read",
            )
            in perms
        )
        assert (
            Permission(
                uri=f"blob://{cluster_name}/{fake_bucket.project_name}/"
                f"{fake_bucket.name}",
                action="read",
            )
            in perms
        )

    def test_write_permissions(
        self, cluster_name: str, service: PermissionsService, fake_bucket: UserBucket
    ) -> None:
        perms = service.get_bucket_write_perms(fake_bucket)
        assert len(perms) == 2
        assert (
            Permission(
                uri=f"blob://{cluster_name}/{fake_bucket.project_name}/"
                f"{fake_bucket.id}",
                action="write",
            )
            in perms
        )
        assert (
            Permission(
                uri=f"blob://{cluster_name}/{fake_bucket.project_name}/"
                f"{fake_bucket.name}",
                action="write",
            )
            in perms
        )

    def test_read_permissions_with_org(
        self,
        cluster_name: str,
        service: PermissionsService,
        fake_bucket_with_org: UserBucket,
    ) -> None:
        perms = service.get_bucket_read_perms(fake_bucket_with_org)
        assert len(perms) == 2
        assert (
            Permission(
                uri=f"blob://{cluster_name}/{fake_bucket_with_org.org_name}/"
                f"{fake_bucket_with_org.project_name}/{fake_bucket_with_org.id}",
                action="read",
            )
            in perms
        )
        assert (
            Permission(
                uri=f"blob://{cluster_name}/{fake_bucket_with_org.org_name}/"
                f"{fake_bucket_with_org.project_name}/{fake_bucket_with_org.name}",
                action="read",
            )
            in perms
        )

    def test_write_permissions_with_org(
        self,
        cluster_name: str,
        service: PermissionsService,
        fake_bucket_with_org: UserBucket,
    ) -> None:
        perms = service.get_bucket_write_perms(fake_bucket_with_org)
        assert len(perms) == 2
        assert (
            Permission(
                uri=f"blob://{cluster_name}/{fake_bucket_with_org.org_name}/"
                f"{fake_bucket_with_org.project_name}/{fake_bucket_with_org.id}",
                action="write",
            )
            in perms
        )
        assert (
            Permission(
                uri=f"blob://{cluster_name}/{fake_bucket_with_org.org_name}/"
                f"{fake_bucket_with_org.project_name}/{fake_bucket_with_org.name}",
                action="write",
            )
            in perms
        )

    async def test_checker_1(
        self,
        cluster_name: str,
        mock_auth_client: MockAuthClient,
        service: PermissionsService,
        fake_bucket: UserBucket,
    ) -> None:
        project_name = fake_bucket.project_name
        mock_auth_client.perm_tree_to_return = ClientSubTreeViewRoot(
            scheme="blob",
            path=f"/{cluster_name}",
            sub_tree=ClientAccessSubTreeView(
                action="list",
                children={
                    project_name: ClientAccessSubTreeView(
                        action="write",
                        children={},
                    ),
                    "another-project": ClientAccessSubTreeView(
                        action="list",
                        children={
                            "fully-shared": ClientAccessSubTreeView(
                                action="write",
                                children={},
                            ),
                            "read-shared": ClientAccessSubTreeView(
                                action="read",
                                children={},
                            ),
                        },
                    ),
                },
            ),
        )
        checker = await service.get_perms_checker(fake_bucket.owner)
        assert checker.can_read(fake_bucket)
        assert checker.can_write(fake_bucket)
        fake_bucket = replace(
            fake_bucket, project_name="another-project", name="not-listed"
        )
        assert not checker.can_read(fake_bucket)
        assert not checker.can_write(fake_bucket)
        fake_bucket = replace(
            fake_bucket, project_name="another-project", name="read-shared"
        )
        assert checker.can_read(fake_bucket)
        assert not checker.can_write(fake_bucket)
        fake_bucket = replace(
            fake_bucket, project_name="another-project", name="fully-shared"
        )
        assert checker.can_read(fake_bucket)
        assert checker.can_write(fake_bucket)
        fake_bucket = replace(
            fake_bucket, project_name="third-project", name="fully-shared"
        )
        assert not checker.can_read(fake_bucket)
        assert not checker.can_write(fake_bucket)
