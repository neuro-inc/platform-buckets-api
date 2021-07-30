import pytest

from platform_buckets_api.kube_client import KubeClient
from platform_buckets_api.kube_storage import K8SStorage
from platform_buckets_api.storage import Storage
from tests.unit.test_storage import TestStorage as _TestStorage


pytestmark = pytest.mark.asyncio


class TestK8SStorage(_TestStorage):
    @pytest.fixture()
    def storage(self, kube_client: KubeClient) -> Storage:  # type: ignore
        return K8SStorage(kube_client)
