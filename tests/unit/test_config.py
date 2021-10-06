import base64
import json
from pathlib import Path
from typing import Any, Dict

import pytest
from yarl import URL

from platform_buckets_api.config import (
    AWSProviderConfig,
    AzureProviderConfig,
    Config,
    CORSConfig,
    EMCECSProviderConfig,
    GCPProviderConfig,
    KubeClientAuthType,
    KubeConfig,
    MinioProviderConfig,
    OpenStackProviderConfig,
    PlatformAuthConfig,
    SentryConfig,
    ServerConfig,
    ZipkinConfig,
)
from platform_buckets_api.config_factory import EnvironConfigFactory


CA_DATA_PEM = "this-is-certificate-authority-public-key"
TOKEN = "this-is-token"


@pytest.fixture()
def cert_authority_path(tmp_path: Path) -> str:
    ca_path = tmp_path / "ca.crt"
    ca_path.write_text(CA_DATA_PEM)
    return str(ca_path)


@pytest.fixture()
def token_path(tmp_path: Path) -> str:
    token_path = tmp_path / "token"
    token_path.write_text(TOKEN)
    return str(token_path)


def test_create(cert_authority_path: str, token_path: str) -> None:
    environ: Dict[str, Any] = {
        "NP_BUCKETS_API_HOST": "0.0.0.0",
        "NP_BUCKETS_API_PORT": 8080,
        "NP_BUCKETS_API_PLATFORM_AUTH_URL": "http://platformauthapi/api/v1",
        "NP_BUCKETS_API_PLATFORM_AUTH_TOKEN": "platform-auth-token",
        "NP_CORS_ORIGINS": "https://domain1.com,http://do.main",
        "NP_BUCKETS_API_ENABLE_DOCS": "true",
        "NP_ZIPKIN_URL": "http://zipkin:9411",
        "NP_SENTRY_DSN": "https://test.com",
        "NP_SENTRY_CLUSTER_NAME": "test",
        "NP_CLUSTER_NAME": "test-cluster",
        "NP_BUCKET_PROVIDER_TYPE": "aws",
        "NP_AWS_ACCESS_KEY_ID": "key-id",
        "NP_AWS_SECRET_ACCESS_KEY": "key-secret",
        "NP_AWS_REGION_NAME": "us-east-2",
        "NP_AWS_S3_ROLE_ARN": "role-arn-here",
        "NP_BUCKETS_API_K8S_API_URL": "https://localhost:8443",
        "NP_BUCKETS_API_K8S_AUTH_TYPE": "token",
        "NP_BUCKETS_API_K8S_CA_PATH": cert_authority_path,
        "NP_BUCKETS_API_K8S_TOKEN_PATH": token_path,
        "NP_BUCKETS_API_K8S_AUTH_CERT_PATH": "/cert_path",
        "NP_BUCKETS_API_K8S_AUTH_CERT_KEY_PATH": "/cert_key_path",
        "NP_BUCKETS_API_K8S_NS": "other-namespace",
        "NP_BUCKETS_API_K8S_CLIENT_CONN_TIMEOUT": "111",
        "NP_BUCKETS_API_K8S_CLIENT_READ_TIMEOUT": "222",
        "NP_BUCKETS_API_K8S_CLIENT_WATCH_TIMEOUT": "555",
        "NP_BUCKETS_API_K8S_CLIENT_CONN_POOL_SIZE": "333",
        "NP_BUCKETS_API_K8S_STORAGE_CLASS": "some-class",
    }
    config = EnvironConfigFactory(environ).create()
    assert config == Config(
        server=ServerConfig(host="0.0.0.0", port=8080),
        platform_auth=PlatformAuthConfig(
            url=URL("http://platformauthapi/api/v1"), token="platform-auth-token"
        ),
        cors=CORSConfig(["https://domain1.com", "http://do.main"]),
        kube=KubeConfig(
            endpoint_url="https://localhost:8443",
            cert_authority_data_pem=CA_DATA_PEM,
            auth_type=KubeClientAuthType.TOKEN,
            token=TOKEN,
            auth_cert_path="/cert_path",
            auth_cert_key_path="/cert_key_path",
            namespace="other-namespace",
            client_conn_timeout_s=111,
            client_read_timeout_s=222,
            client_watch_timeout_s=555,
            client_conn_pool_size=333,
        ),
        zipkin=ZipkinConfig(url=URL("http://zipkin:9411")),
        sentry=SentryConfig(dsn=URL("https://test.com"), cluster_name="test"),
        enable_docs=True,
        cluster_name="test-cluster",
        bucket_provider=AWSProviderConfig(
            access_key_id="key-id",
            secret_access_key="key-secret",
            region_name="us-east-2",
            s3_role_arn="role-arn-here",
        ),
    )


def test_create_minio() -> None:
    environ: Dict[str, Any] = {
        "NP_BUCKET_PROVIDER_TYPE": "minio",
        "NP_MINIO_ACCESS_KEY_ID": "key-id",
        "NP_MINIO_SECRET_ACCESS_KEY": "key-secret",
        "NP_MINIO_REGION_NAME": "region",
        "NP_MINIO_ENDPOINT_URL": "https://play.min.io",
        "NP_MINIO_ENDPOINT_PUBLIC_URL": "https://public.play.min.io",
    }
    config = EnvironConfigFactory(environ).create_bucket_provider()
    assert config == MinioProviderConfig(
        access_key_id="key-id",
        secret_access_key="key-secret",
        region_name="region",
        endpoint_url=URL("https://play.min.io"),
        endpoint_public_url=URL("https://public.play.min.io"),
    )


def test_create_azure() -> None:
    environ: Dict[str, Any] = {
        "NP_BUCKET_PROVIDER_TYPE": "azure",
        "NP_AZURE_STORAGE_ACCOUNT_URL": "https://some.url.windows.com/",
        "NP_AZURE_STORAGE_CREDENTIAL": "secret",
    }
    config = EnvironConfigFactory(environ).create_bucket_provider()
    assert config == AzureProviderConfig(
        endpoint_url=URL("https://some.url.windows.com/"),
        credential="secret",
    )


def test_create_gcs() -> None:
    environ: Dict[str, Any] = {
        "NP_BUCKET_PROVIDER_TYPE": "gcp",
        "NP_GCP_SERVICE_ACCOUNT_KEY_JSON_B64": base64.b64encode(
            json.dumps({"key": "value"}).encode()
        ).decode(),
    }
    config = EnvironConfigFactory(environ).create_bucket_provider()
    assert config == GCPProviderConfig(key_json={"key": "value"})


def test_create_emc_ecs() -> None:
    environ: Dict[str, Any] = {
        "NP_BUCKET_PROVIDER_TYPE": "emc_ecs",
        "NP_EMC_ECS_ACCESS_KEY_ID": "key-id",
        "NP_EMC_ECS_SECRET_ACCESS_KEY": "key-secret",
        "NP_EMC_ECS_S3_ROLE_URN": "role-urn",
        "NP_EMC_ECS_S3_ENDPOINT_URL": "https://emc-ecs.s3",
        "NP_EMC_ECS_MANAGEMENT_ENDPOINT_URL": "https://emc-ecs.management",
    }
    config = EnvironConfigFactory(environ).create_bucket_provider()
    assert config == EMCECSProviderConfig(
        access_key_id="key-id",
        secret_access_key="key-secret",
        s3_role_urn="role-urn",
        s3_endpoint_url=URL("https://emc-ecs.s3"),
        management_endpoint_url=URL("https://emc-ecs.management"),
    )


def test_create_open_stack() -> None:
    environ: Dict[str, Any] = {
        "NP_BUCKET_PROVIDER_TYPE": "open_stack",
        "NP_OS_ACCOUNT_ID": "key-id",
        "NP_OS_PASSWORD": "password",
        "NP_OS_ENDPOINT_URL": "https://os.management",
        "NP_OS_S3_ENDPOINT_URL": "https://os.s3",
        "NP_OS_REGION_NAME": "region",
    }
    config = EnvironConfigFactory(environ).create_bucket_provider()
    assert config == OpenStackProviderConfig(
        account_id="key-id",
        password="password",
        endpoint_url=URL("https://os.management"),
        s3_endpoint_url=URL("https://os.s3"),
        region_name="region",
    )
