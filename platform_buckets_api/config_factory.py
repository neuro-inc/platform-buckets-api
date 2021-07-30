import logging
import os
from pathlib import Path
from typing import Dict, Optional, Sequence, Union

from yarl import URL

from .config import (
    AWSProviderConfig,
    BucketsProviderType,
    Config,
    CORSConfig,
    KubeClientAuthType,
    KubeConfig,
    PlatformAuthConfig,
    SentryConfig,
    ServerConfig,
    ZipkinConfig,
)


logger = logging.getLogger(__name__)


class EnvironConfigFactory:
    def __init__(self, environ: Optional[Dict[str, str]] = None) -> None:
        self._environ = environ or os.environ

    def create(self) -> Config:

        cluster_name = self._environ.get("NP_CLUSTER_NAME", "")
        enable_docs = self._environ.get("NP_BUCKETS_API_ENABLE_DOCS", "false") == "true"
        return Config(
            server=self._create_server(),
            platform_auth=self._create_platform_auth(),
            kube=self.create_kube(),
            cors=self.create_cors(),
            zipkin=self.create_zipkin(),
            sentry=self.create_sentry(),
            enable_docs=enable_docs,
            cluster_name=cluster_name,
            bucket_provider=self.create_bucket_provider(),
        )

    def _create_server(self) -> ServerConfig:
        host = self._environ.get("NP_BUCKETS_API_HOST", ServerConfig.host)
        port = int(self._environ.get("NP_BUCKETS_API_PORT", ServerConfig.port))
        return ServerConfig(host=host, port=port)

    def _create_platform_auth(self) -> PlatformAuthConfig:
        url = URL(self._environ["NP_BUCKETS_API_PLATFORM_AUTH_URL"])
        token = self._environ["NP_BUCKETS_API_PLATFORM_AUTH_TOKEN"]
        return PlatformAuthConfig(url=url, token=token)

    def create_cors(self) -> CORSConfig:
        origins: Sequence[str] = CORSConfig.allowed_origins
        origins_str = self._environ.get("NP_CORS_ORIGINS", "").strip()
        if origins_str:
            origins = origins_str.split(",")
        return CORSConfig(allowed_origins=origins)

    def create_zipkin(self) -> Optional[ZipkinConfig]:
        if "NP_ZIPKIN_URL" not in self._environ:
            return None

        url = URL(self._environ["NP_ZIPKIN_URL"])
        app_name = self._environ.get("NP_ZIPKIN_APP_NAME", ZipkinConfig.app_name)
        sample_rate = float(
            self._environ.get("NP_ZIPKIN_SAMPLE_RATE", ZipkinConfig.sample_rate)
        )
        return ZipkinConfig(url=url, app_name=app_name, sample_rate=sample_rate)

    def create_sentry(self) -> Optional[SentryConfig]:
        if "NP_SENTRY_DSN" not in self._environ:
            return None

        return SentryConfig(
            dsn=URL(self._environ["NP_SENTRY_DSN"]),
            cluster_name=self._environ["NP_SENTRY_CLUSTER_NAME"],
            app_name=self._environ.get("NP_SENTRY_APP_NAME", SentryConfig.app_name),
            sample_rate=float(
                self._environ.get("NP_SENTRY_SAMPLE_RATE", SentryConfig.sample_rate)
            ),
        )

    def create_bucket_provider(self) -> Union[AWSProviderConfig]:
        type = self._environ["NP_BUCKET_PROVIDER_TYPE"]
        if type == BucketsProviderType.AWS:
            return AWSProviderConfig(
                access_key_id=self._environ["NP_AWS_ACCESS_KEY_ID"],
                secret_access_key=self._environ["NP_AWS_SECRET_ACCESS_KEY"],
                region_name=self._environ.get(
                    "NP_AWS_REGION_NAME", AWSProviderConfig.region_name
                ),
            )
        else:
            raise ValueError(f"Unknown bucket provider type {type}")

    def create_kube(self) -> KubeConfig:
        endpoint_url = self._environ["NP_BUCKETS_API_K8S_API_URL"]
        auth_type = KubeClientAuthType(
            self._environ.get(
                "NP_BUCKETS_API_K8S_AUTH_TYPE", KubeConfig.auth_type.value
            )
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
            namespace=self._environ.get("NP_BUCKETS_API_K8S_NS", KubeConfig.namespace),
            client_conn_timeout_s=int(
                self._environ.get("NP_BUCKETS_API_K8S_CLIENT_CONN_TIMEOUT")
                or KubeConfig.client_conn_timeout_s
            ),
            client_read_timeout_s=int(
                self._environ.get("NP_BUCKETS_API_K8S_CLIENT_READ_TIMEOUT")
                or KubeConfig.client_read_timeout_s
            ),
            client_watch_timeout_s=int(
                self._environ.get("NP_BUCKETS_API_K8S_CLIENT_WATCH_TIMEOUT")
                or KubeConfig.client_watch_timeout_s
            ),
            client_conn_pool_size=int(
                self._environ.get("NP_BUCKETS_API_K8S_CLIENT_CONN_POOL_SIZE")
                or KubeConfig.client_conn_pool_size
            ),
        )
