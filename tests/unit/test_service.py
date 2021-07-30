from typing import Optional

import pytest
from neuro_auth_client import AuthClient, ClientAccessSubTreeView, ClientSubTreeViewRoot

from platform_buckets_api.providers import BucketPermission
from platform_buckets_api.service import Service
from platform_buckets_api.storage import Storage
from tests.mocks import MockBucketProvider


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


class TestService:
    @pytest.fixture
    def cluster_name(self) -> str:
        return "test-cluster"

    @pytest.fixture
    def mock_auth_client(self, cluster_name: str) -> MockAuthClient:
        client = MockAuthClient()
        client.perm_tree_to_return = ClientSubTreeViewRoot(
            path=f"buckets://{cluster_name}",
            sub_tree=ClientAccessSubTreeView(
                action="list",
                children={
                    "test-user": ClientAccessSubTreeView(
                        action="write",
                        children={},
                    )
                },
            ),
        )
        return client

    @pytest.fixture
    def mock_provider(self) -> MockBucketProvider:
        return MockBucketProvider()

    @pytest.fixture
    def service(
        self,
        in_memory_storage: Storage,
        mock_auth_client: MockAuthClient,
        mock_provider: MockBucketProvider,
        cluster_name: str,
    ) -> Service:
        return Service(
            storage=in_memory_storage,
            auth_client=mock_auth_client,
            bucket_provider=mock_provider,
            cluster_name=cluster_name,
        )

    async def test_bucket_create(
        self, service: Service, mock_provider: MockBucketProvider
    ) -> None:
        bucket, credentials = await service.create_bucket(
            name="test-bucket",
            owner="test-user",
        )
        assert mock_provider.created_buckets == [bucket.provider_bucket]
        assert bucket.provider_bucket.name.startswith("neuro-pl-test-bucket-test-user")

        assert mock_provider.created_roles == [credentials.role]
        perms = mock_provider.role_to_permissions[credentials.role.id]
        assert perms == {
            BucketPermission(
                bucket=bucket.provider_bucket,
                write=True,
            )
        }

    async def test_bucket_create_second_one(
        self, service: Service, mock_provider: MockBucketProvider
    ) -> None:
        bucket1, credentials1 = await service.create_bucket(
            name="test-bucket-1",
            owner="test-user",
        )
        bucket2, credentials2 = await service.create_bucket(
            name="test-bucket-2",
            owner="test-user",
        )
        assert credentials1 == credentials2
        assert mock_provider.created_buckets == [
            bucket1.provider_bucket,
            bucket2.provider_bucket,
        ]
        assert mock_provider.created_roles == [credentials1.role]
        perms = mock_provider.role_to_permissions[credentials1.role.id]
        assert set(perms) == {
            BucketPermission(
                bucket=bucket1.provider_bucket,
                write=True,
            ),
            BucketPermission(
                bucket=bucket2.provider_bucket,
                write=True,
            ),
        }
