from dataclasses import replace
from typing import Optional

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


pytestmark = pytest.mark.asyncio


class MockAuthClient(AuthClient):
    def __init__(self) -> None:
        self.perm_tree_to_return = ClientSubTreeViewRoot(
            path="",
            sub_tree=ClientAccessSubTreeView(
                action="read",
                children={},
            ),
        )

    async def get_permissions_tree(
        self, name: str, resource: str, depth: Optional[int] = None
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
            provider_bucket=None,  # type: ignore
        )

    def test_create_permissions(
        self, cluster_name: str, service: PermissionsService, fake_user: User
    ) -> None:
        perms = service.get_create_bucket_perms(fake_user)
        assert len(perms) == 1
        assert perms[0].uri == f"blob://{cluster_name}/{fake_user.name}"
        assert perms[0].action == "write"

    def test_read_permissions(
        self, cluster_name: str, service: PermissionsService, fake_bucket: UserBucket
    ) -> None:
        perms = service.get_bucket_read_perms(fake_bucket)
        assert len(perms) == 2
        assert (
            Permission(
                uri=f"blob://{cluster_name}/{fake_bucket.owner}/{fake_bucket.id}",
                action="read",
            )
            in perms
        )
        assert (
            Permission(
                uri=f"blob://{cluster_name}/{fake_bucket.owner}/{fake_bucket.name}",
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
                uri=f"blob://{cluster_name}/{fake_bucket.owner}/{fake_bucket.id}",
                action="write",
            )
            in perms
        )
        assert (
            Permission(
                uri=f"blob://{cluster_name}/{fake_bucket.owner}/{fake_bucket.name}",
                action="write",
            )
            in perms
        )

    async def test_checker(
        self,
        cluster_name: str,
        mock_auth_client: MockAuthClient,
        service: PermissionsService,
        fake_bucket: UserBucket,
    ) -> None:
        mock_auth_client.perm_tree_to_return = ClientSubTreeViewRoot(
            path=f"/{cluster_name}/",
            sub_tree=ClientAccessSubTreeView(
                action="list",
                children={
                    fake_bucket.owner: ClientAccessSubTreeView(
                        action="write",
                        children={},
                    ),
                    "another-user": ClientAccessSubTreeView(
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
        fake_bucket = replace(fake_bucket, owner="another-user", name="not-listed")
        assert not checker.can_read(fake_bucket)
        assert not checker.can_write(fake_bucket)
        fake_bucket = replace(fake_bucket, owner="another-user", name="read-shared")
        assert checker.can_read(fake_bucket)
        assert not checker.can_write(fake_bucket)
        fake_bucket = replace(fake_bucket, owner="another-user", name="fully-shared")
        assert checker.can_read(fake_bucket)
        assert checker.can_write(fake_bucket)
        fake_bucket = replace(fake_bucket, owner="third-user", name="fully-shared")
        assert not checker.can_read(fake_bucket)
        assert not checker.can_write(fake_bucket)
