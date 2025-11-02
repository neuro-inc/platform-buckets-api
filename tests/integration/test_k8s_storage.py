import pytest

from collections.abc import AsyncIterator
from apolo_kube_client import KubeClient, KubeClientSelector, KubeConfig
from platform_buckets_api.kube_storage import K8SBucketsStorage, K8SCredentialsStorage
from platform_buckets_api.storage import BucketsStorage, CredentialsStorage
from tests.unit.test_storage import (
    TestBucketsStorage as _TestBucketsStorage,
    TestCredentialsStorage as _TestCredentialsStorage,
)


@pytest.fixture
async def kube_selector(kube_config: KubeConfig) -> AsyncIterator[KubeClientSelector]:
    async with KubeClientSelector(config=kube_config) as kube_client_selector:
        yield kube_client_selector


class TestK8SBucketsStorage(_TestBucketsStorage):
    @pytest.fixture()
    def storage(self, kube_selector: KubeClientSelector) -> BucketsStorage:
        return K8SBucketsStorage(kube_selector)


class TestK8SCredentialsStorage(_TestCredentialsStorage):
    @pytest.fixture()
    def storage(self, kube_client: KubeClient) -> CredentialsStorage:
        return K8SCredentialsStorage(kube_client)
