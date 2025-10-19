import base64
import json
import logging
import os
from pathlib import Path

from apolo_events_client import EventsClientConfig

from apolo_kube_client import KubeClientAuthType, KubeConfig
from yarl import URL

from .config import (
    AWSProviderConfig,
    AzureProviderConfig,
    BucketsProviderType,
    Config,
    EMCECSProviderConfig,
    GCPProviderConfig,
    MinioProviderConfig,
    OpenStackProviderConfig,
    PlatformAuthConfig,
    ServerConfig,
)

logger = logging.getLogger(__name__)


class EnvironConfigFactory:
    def __init__(self, environ: dict[str, str] | None = None) -> None:
        self._environ = environ or os.environ

    def _get_url(self, name: str) -> URL | None:
        value = self._environ[name]
        if value == "-":
            return None
        else:
            return URL(value)

    def create(self) -> Config:
        cluster_name = self._environ.get("NP_CLUSTER_NAME", "")
        enable_docs = self._environ.get("NP_BUCKETS_API_ENABLE_DOCS", "false") == "true"
        disable_creation = (
            self._environ.get("NP_BUCKETS_API_DISABLE_CREATION", "false") == "true"
        )
        return Config(
            server=self._create_server(),
            platform_auth=self._create_platform_auth(),
            kube=self.create_kube(),
            enable_docs=enable_docs,
            disable_creation=disable_creation,
            cluster_name=cluster_name,
            bucket_provider=self.create_bucket_provider(),
            events=self.create_events(),
        )

    def _create_server(self) -> ServerConfig:
        host = self._environ.get("NP_BUCKETS_API_HOST", ServerConfig.host)
        port = int(self._environ.get("NP_BUCKETS_API_PORT", ServerConfig.port))
        return ServerConfig(host=host, port=port)

    def _create_platform_auth(self) -> PlatformAuthConfig:
        url = self._get_url("NP_BUCKETS_API_PLATFORM_AUTH_URL")
        token = self._environ["NP_BUCKETS_API_PLATFORM_AUTH_TOKEN"]
        return PlatformAuthConfig(url=url, token=token)

    def create_bucket_provider(
        self,
    ) -> (
        AWSProviderConfig
        | MinioProviderConfig
        | AzureProviderConfig
        | GCPProviderConfig
        | EMCECSProviderConfig
        | OpenStackProviderConfig
    ):
        type_ = self._environ["NP_BUCKET_PROVIDER_TYPE"]
        if type_ == BucketsProviderType.AWS:
            return AWSProviderConfig(
                s3_role_arn=self._environ["NP_AWS_S3_ROLE_ARN"],
                access_key_id=self._environ.get("NP_AWS_ACCESS_KEY_ID") or None,
                secret_access_key=self._environ.get("NP_AWS_SECRET_ACCESS_KEY") or None,
                endpoint_url=(
                    URL(self._environ["NP_AWS_ENDPOINT_URL"])
                    if "NP_AWS_ENDPOINT_URL" in self._environ
                    else None
                ),
                region_name=self._environ.get("NP_AWS_REGION_NAME")
                or AWSProviderConfig.region_name,
            )
        elif type_ == BucketsProviderType.MINIO:
            return MinioProviderConfig(
                access_key_id=self._environ["NP_MINIO_ACCESS_KEY_ID"],
                secret_access_key=self._environ["NP_MINIO_SECRET_ACCESS_KEY"],
                region_name=self._environ["NP_MINIO_REGION_NAME"],
                endpoint_url=URL(self._environ["NP_MINIO_ENDPOINT_URL"]),
                endpoint_public_url=URL(self._environ["NP_MINIO_ENDPOINT_PUBLIC_URL"]),
            )
        elif type_ == BucketsProviderType.AZURE:
            return AzureProviderConfig(
                endpoint_url=URL(self._environ["NP_AZURE_STORAGE_ACCOUNT_URL"]),
                credential=self._environ["NP_AZURE_STORAGE_CREDENTIAL"],
            )
        elif type_ == BucketsProviderType.GCP:
            key_raw = self._environ["NP_GCP_SERVICE_ACCOUNT_KEY_JSON_B64"]
            key_json = json.loads(base64.b64decode(key_raw).decode())
            return GCPProviderConfig(
                key_json=key_json,
            )
        elif type_ == BucketsProviderType.EMC_ECS:
            return EMCECSProviderConfig(
                s3_role_urn=self._environ["NP_EMC_ECS_S3_ROLE_URN"],
                access_key_id=self._environ["NP_EMC_ECS_ACCESS_KEY_ID"],
                secret_access_key=self._environ["NP_EMC_ECS_SECRET_ACCESS_KEY"],
                s3_endpoint_url=URL(self._environ["NP_EMC_ECS_S3_ENDPOINT_URL"]),
                management_endpoint_url=URL(
                    self._environ["NP_EMC_ECS_MANAGEMENT_ENDPOINT_URL"]
                ),
            )
        elif type_ == BucketsProviderType.OPEN_STACK:
            return OpenStackProviderConfig(
                account_id=self._environ["NP_OS_ACCOUNT_ID"],
                password=self._environ["NP_OS_PASSWORD"],
                endpoint_url=URL(self._environ["NP_OS_ENDPOINT_URL"]),
                s3_endpoint_url=URL(self._environ["NP_OS_S3_ENDPOINT_URL"]),
                region_name=self._environ["NP_OS_REGION_NAME"],
            )
        else:
            raise ValueError(f"Unknown bucket provider type {type_}")

    def create_kube(self) -> KubeConfig:
        endpoint_url = self._environ["NP_BUCKETS_API_K8S_API_URL"]
        auth_type = KubeClientAuthType(
            self._environ.get("NP_BUCKETS_API_K8S_AUTH_TYPE", KubeClientAuthType.NONE)
        )
        ca_path = self._environ.get("NP_BUCKETS_API_K8S_CA_PATH")
        ca_data = Path(ca_path).read_text() if ca_path else None

        token_path = self._environ.get("NP_BUCKETS_API_K8S_TOKEN_PATH")
        token = Path(token_path).read_text() if token_path else None

        return KubeConfig(
            endpoint_url=endpoint_url,
            cert_authority_data_pem=ca_data,
            auth_type=auth_type,
            auth_cert_path=self._environ.get("NP_BUCKETS_API_K8S_AUTH_CERT_PATH"),
            auth_cert_key_path=self._environ.get(
                "NP_BUCKETS_API_K8S_AUTH_CERT_KEY_PATH"
            ),
            token=token,
            token_path=token_path,
            namespace=self._environ.get(
                "NP_BUCKETS_API_K8S_NS", KubeConfig.model_fields["namespace"].default
            ),
            client_conn_timeout_s=int(
                self._environ.get("NP_BUCKETS_API_K8S_CLIENT_CONN_TIMEOUT")
                or KubeConfig.model_fields["client_conn_timeout_s"].default
            ),
            client_read_timeout_s=int(
                self._environ.get("NP_BUCKETS_API_K8S_CLIENT_READ_TIMEOUT")
                or KubeConfig.model_fields["client_read_timeout_s"].default
            ),
            client_watch_timeout_s=int(
                self._environ.get("NP_BUCKETS_API_K8S_CLIENT_WATCH_TIMEOUT")
                or KubeConfig.model_fields["client_watch_timeout_s"].default
            ),
            client_conn_pool_size=int(
                self._environ.get("NP_BUCKETS_API_K8S_CLIENT_CONN_POOL_SIZE")
                or KubeConfig.model_fields["client_conn_pool_size"].default
            ),
        )

    def create_events(self) -> EventsClientConfig | None:
        events_url = self._environ.get("NP_PLATFORM_EVENTS_URL")
        if not events_url:
            return None
        return EventsClientConfig(
            url=URL(events_url),
            token=self._environ["NP_PLATFORM_EVENTS_TOKEN"],
            name="platform-buckets",
        )
