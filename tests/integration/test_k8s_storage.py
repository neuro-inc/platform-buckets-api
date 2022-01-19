import pytest

from platform_buckets_api.kube_client import KubeClient
from platform_buckets_api.kube_storage import K8SBucketsStorage, K8SCredentialsStorage
from platform_buckets_api.storage import BucketsStorage, CredentialsStorage

from tests.unit.test_storage import (
    TestBucketsStorage as _TestBucketsStorage,
    TestCredentialsStorage as _TestCredentialsStorage,
)


class TestK8SBucketsStorage(_TestBucketsStorage):
    @pytest.fixture()
    def storage(self, kube_client: KubeClient) -> BucketsStorage:  # type: ignore
        return K8SBucketsStorage(kube_client)


class TestK8SCredentialsStorage(_TestCredentialsStorage):
    @pytest.fixture()
    def storage(self, kube_client: KubeClient) -> CredentialsStorage:  # type: ignore
        return K8SCredentialsStorage(kube_client)
