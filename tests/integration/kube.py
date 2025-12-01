import asyncio
import json
import subprocess
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest

from apolo_kube_client import (
    KubeClient,
    KubeClientAuthType,
    KubeConfig,
    ResourceNotFound,
)


@pytest.fixture(scope="session")
def kube_config_payload() -> dict[str, Any]:
    result = subprocess.run(
        ["kubectl", "config", "view", "-o", "json"], stdout=subprocess.PIPE
    )
    payload_str = result.stdout.decode().rstrip()
    return json.loads(payload_str)


@pytest.fixture(scope="session")
def kube_config_cluster_payload(kube_config_payload: dict[str, Any]) -> Any:
    cluster_name = "minikube"
    clusters = {
        cluster["name"]: cluster["cluster"]
        for cluster in kube_config_payload["clusters"]
    }
    return clusters[cluster_name]


@pytest.fixture(scope="session")
def kube_config_user_payload(kube_config_payload: dict[str, Any]) -> Any:
    user_name = "minikube"
    users = {user["name"]: user["user"] for user in kube_config_payload["users"]}
    return users[user_name]


@pytest.fixture(scope="session")
def cert_authority_data_pem(kube_config_cluster_payload: dict[str, Any]) -> str | None:
    ca_path = kube_config_cluster_payload["certificate-authority"]
    if ca_path:
        return Path(ca_path).read_text()
    return None


@pytest.fixture
async def kube_config(
    kube_config_cluster_payload: dict[str, Any],
    kube_config_user_payload: dict[str, Any],
    cert_authority_data_pem: str | None,
) -> KubeConfig:
    cluster = kube_config_cluster_payload
    user = kube_config_user_payload
    kube_config = KubeConfig(
        endpoint_url=cluster["server"],
        cert_authority_data_pem=cert_authority_data_pem,
        auth_type=KubeClientAuthType.CERTIFICATE,
        auth_cert_path=user["client-certificate"],
        auth_cert_key_path=user["client-key"],
    )
    return kube_config


@pytest.fixture
def kube_client_factory() -> Callable[[KubeConfig], KubeClient]:
    def make_kube_client(kube_config: KubeConfig) -> KubeClient:
        return KubeClient(config=kube_config)

    return make_kube_client


@pytest.fixture
async def kube_client(
    kube_config: KubeConfig,
    kube_client_factory: Callable[[KubeConfig], KubeClient],
) -> AsyncIterator[KubeClient]:
    client = kube_client_factory(kube_config)

    async def _clean_k8s(kube_client: KubeClient) -> None:
        bucket_list = await kube_client.neuromation_io_v1.user_bucket.get_list(
            all_namespaces=True
        )
        for bucket in bucket_list.items:
            assert bucket.metadata.name is not None
            try:
                await kube_client.neuromation_io_v1.user_bucket.delete(
                    name=bucket.metadata.name,
                    namespace=bucket.metadata.namespace,
                )
            except ResourceNotFound:
                pass

        creds_list = (
            await kube_client.neuromation_io_v1.persistent_bucket_credential.get_list(
                all_namespaces=True
            )
        )
        for creds in creds_list.items:
            assert creds.metadata.name is not None
            try:
                await kube_client.neuromation_io_v1.persistent_bucket_credential.delete(
                    name=creds.metadata.name,
                    namespace=creds.metadata.namespace,
                )
            except ResourceNotFound:
                pass

    async with client:
        await _clean_k8s(client)
        yield client
        await _clean_k8s(client)
    await asyncio.sleep(0.01)
