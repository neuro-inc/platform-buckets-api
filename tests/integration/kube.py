import asyncio
import json
import subprocess
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Dict, Optional

import pytest

from platform_buckets_api.config import KubeConfig
from platform_buckets_api.kube_client import KubeClient, ResourceNotFound


@pytest.fixture(scope="session")
def kube_config_payload() -> Dict[str, Any]:
    result = subprocess.run(
        ["kubectl", "config", "view", "-o", "json"], stdout=subprocess.PIPE
    )
    payload_str = result.stdout.decode().rstrip()
    return json.loads(payload_str)


@pytest.fixture(scope="session")
def kube_config_cluster_payload(kube_config_payload: Dict[str, Any]) -> Any:
    cluster_name = "minikube"
    clusters = {
        cluster["name"]: cluster["cluster"]
        for cluster in kube_config_payload["clusters"]
    }
    return clusters[cluster_name]


@pytest.fixture(scope="session")
def kube_config_user_payload(kube_config_payload: Dict[str, Any]) -> Any:
    user_name = "minikube"
    users = {user["name"]: user["user"] for user in kube_config_payload["users"]}
    return users[user_name]


@pytest.fixture(scope="session")
def cert_authority_data_pem(
    kube_config_cluster_payload: Dict[str, Any]
) -> Optional[str]:
    ca_path = kube_config_cluster_payload["certificate-authority"]
    if ca_path:
        return Path(ca_path).read_text()
    return None


@pytest.fixture
async def kube_config(
    kube_config_cluster_payload: Dict[str, Any],
    kube_config_user_payload: Dict[str, Any],
    cert_authority_data_pem: Optional[str],
) -> KubeConfig:
    cluster = kube_config_cluster_payload
    user = kube_config_user_payload
    kube_config = KubeConfig(
        endpoint_url=cluster["server"],
        cert_authority_data_pem=cert_authority_data_pem,
        auth_cert_path=user["client-certificate"],
        auth_cert_key_path=user["client-key"],
        namespace="default",
    )
    return kube_config


@pytest.fixture
def kube_client_factory() -> Callable[[KubeConfig], KubeClient]:
    def make_kube_client(kube_config: KubeConfig) -> KubeClient:
        return KubeClient(
            base_url=kube_config.endpoint_url,
            auth_type=kube_config.auth_type,
            cert_authority_data_pem=kube_config.cert_authority_data_pem,
            cert_authority_path=None,  # disabled, see `cert_authority_data_pem`
            auth_cert_path=kube_config.auth_cert_path,
            auth_cert_key_path=kube_config.auth_cert_key_path,
            namespace=kube_config.namespace,
            conn_timeout_s=kube_config.client_conn_timeout_s,
            read_timeout_s=kube_config.client_read_timeout_s,
            watch_timeout_s=kube_config.client_watch_timeout_s,
            conn_pool_size=kube_config.client_conn_pool_size,
        )

    return make_kube_client


@pytest.fixture
async def kube_client(
    kube_config: KubeConfig,
    kube_client_factory: Callable[[KubeConfig], KubeClient],
) -> AsyncIterator[KubeClient]:
    client = kube_client_factory(kube_config)

    async def _clean_k8s(kube_client: KubeClient) -> None:
        for bucket in await kube_client.list_user_buckets():
            try:
                await kube_client.remove_user_bucket(bucket)
            except ResourceNotFound:
                pass
        for creds in await kube_client.list_persistent_credentials():
            try:
                await kube_client.remove_persistent_credentials(creds)
            except ResourceNotFound:
                pass

    async with client:
        await _clean_k8s(client)
        yield client
        await _clean_k8s(client)
    await asyncio.sleep(0.01)
