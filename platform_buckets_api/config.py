import enum
from dataclasses import dataclass, field
from typing import ClassVar, Optional, Sequence, Union

from yarl import URL


@dataclass(frozen=True)
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8080


@dataclass(frozen=True)
class PlatformAuthConfig:
    url: URL
    token: str = field(repr=False)


@dataclass(frozen=True)
class CORSConfig:
    allowed_origins: Sequence[str] = ()


@dataclass(frozen=True)
class ZipkinConfig:
    url: URL
    app_name: str = "platform-buckets-api"
    sample_rate: float = 0.0


@dataclass(frozen=True)
class SentryConfig:
    dsn: URL
    cluster_name: str
    app_name: str = "platform-buckets-api"
    sample_rate: float = 0.0


class BucketsProviderType(str, enum.Enum):
    AWS = "aws"


@dataclass(frozen=True)
class AWSProviderConfig:
    type: ClassVar[BucketsProviderType] = BucketsProviderType.AWS
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    region_name: str = "us-east-1"
    endpoint_url: Optional[str] = None


class KubeClientAuthType(str, enum.Enum):
    NONE = "none"
    TOKEN = "token"
    CERTIFICATE = "certificate"


@dataclass(frozen=True)
class KubeConfig:
    endpoint_url: str
    cert_authority_data_pem: Optional[str] = field(repr=False, default=None)
    cert_authority_path: Optional[str] = None
    auth_type: KubeClientAuthType = KubeClientAuthType.CERTIFICATE
    auth_cert_path: Optional[str] = None
    auth_cert_key_path: Optional[str] = None
    token: Optional[str] = field(repr=False, default=None)
    namespace: str = "default"
    client_conn_timeout_s: int = 300
    client_read_timeout_s: int = 300
    client_watch_timeout_s: int = 1800
    client_conn_pool_size: int = 100


@dataclass(frozen=True)
class Config:
    server: ServerConfig
    platform_auth: PlatformAuthConfig
    kube: KubeConfig
    cors: CORSConfig
    cluster_name: str
    bucket_provider: Union[AWSProviderConfig]
    enable_docs: bool = False
    zipkin: Optional[ZipkinConfig] = None
    sentry: Optional[SentryConfig] = None
