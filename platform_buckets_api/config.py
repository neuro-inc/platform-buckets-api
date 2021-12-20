import enum
from dataclasses import dataclass, field
from typing import ClassVar, Mapping, Optional, Sequence, Union

from google.oauth2.service_account import Credentials as SACredentials
from yarl import URL


@dataclass(frozen=True)
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8080


@dataclass(frozen=True)
class PlatformAuthConfig:
    url: Optional[URL]
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
    MINIO = "minio"
    AZURE = "azure"
    GCP = "gcp"
    EMC_ECS = "emc_ecs"
    OPEN_STACK = "open_stack"


@dataclass(frozen=True)
class AWSProviderConfig:
    type: ClassVar[BucketsProviderType] = BucketsProviderType.AWS
    s3_role_arn: str
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    region_name: str = "us-east-1"
    endpoint_url: Optional[URL] = None


@dataclass(frozen=True)
class MinioProviderConfig:
    type: ClassVar[BucketsProviderType] = BucketsProviderType.MINIO
    access_key_id: str
    secret_access_key: str
    region_name: str
    endpoint_url: URL
    endpoint_public_url: URL


@dataclass(frozen=True)
class AzureProviderConfig:
    type: ClassVar[BucketsProviderType] = BucketsProviderType.AZURE
    endpoint_url: URL
    credential: str


@dataclass(frozen=True)
class GCPProviderConfig:
    type: ClassVar[BucketsProviderType] = BucketsProviderType.GCP
    key_json: Mapping[str, str]

    @property
    def sa_credentials(self) -> SACredentials:
        return SACredentials.from_service_account_info(info=self.key_json)


@dataclass(frozen=True)
class EMCECSProviderConfig:
    type: ClassVar[BucketsProviderType] = BucketsProviderType.EMC_ECS
    s3_role_urn: str
    access_key_id: str
    secret_access_key: str
    s3_endpoint_url: URL
    management_endpoint_url: URL


@dataclass(frozen=True)
class OpenStackProviderConfig:
    type: ClassVar[BucketsProviderType] = BucketsProviderType.OPEN_STACK
    account_id: str
    password: str
    region_name: str
    endpoint_url: URL
    s3_endpoint_url: URL


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
    bucket_provider: Union[
        AWSProviderConfig,
        MinioProviderConfig,
        AzureProviderConfig,
        GCPProviderConfig,
        EMCECSProviderConfig,
        OpenStackProviderConfig,
    ]
    enable_docs: bool = False
    disable_creation: bool = False
    zipkin: Optional[ZipkinConfig] = None
    sentry: Optional[SentryConfig] = None
