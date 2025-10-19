import enum
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import ClassVar

from apolo_events_client import EventsClientConfig

from apolo_kube_client import KubeConfig
from google.oauth2.service_account import Credentials as SACredentials
from yarl import URL


@dataclass(frozen=True)
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8080


@dataclass(frozen=True)
class PlatformAuthConfig:
    url: URL | None
    token: str = field(repr=False)


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
    access_key_id: str | None = field(repr=False, default=None)
    secret_access_key: str | None = field(repr=False, default=None)
    region_name: str = "us-east-1"
    endpoint_url: URL | None = None


@dataclass(frozen=True)
class MinioProviderConfig:
    type: ClassVar[BucketsProviderType] = BucketsProviderType.MINIO
    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)
    region_name: str
    endpoint_url: URL
    endpoint_public_url: URL


@dataclass(frozen=True)
class AzureProviderConfig:
    type: ClassVar[BucketsProviderType] = BucketsProviderType.AZURE
    endpoint_url: URL
    credential: str = field(repr=False)


@dataclass(frozen=True)
class GCPProviderConfig:
    type: ClassVar[BucketsProviderType] = BucketsProviderType.GCP
    key_json: Mapping[str, str] = field(repr=False)

    @property
    def sa_credentials(self) -> SACredentials:
        return SACredentials.from_service_account_info(info=self.key_json)


@dataclass(frozen=True)
class EMCECSProviderConfig:
    type: ClassVar[BucketsProviderType] = BucketsProviderType.EMC_ECS
    s3_role_urn: str
    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)
    s3_endpoint_url: URL
    management_endpoint_url: URL


@dataclass(frozen=True)
class OpenStackProviderConfig:
    type: ClassVar[BucketsProviderType] = BucketsProviderType.OPEN_STACK
    account_id: str
    password: str = field(repr=False)
    region_name: str
    endpoint_url: URL
    s3_endpoint_url: URL


@dataclass(frozen=True)
class Config:
    server: ServerConfig
    platform_auth: PlatformAuthConfig
    kube: KubeConfig
    cluster_name: str
    bucket_provider: (
        AWSProviderConfig
        | MinioProviderConfig
        | AzureProviderConfig
        | GCPProviderConfig
        | EMCECSProviderConfig
        | OpenStackProviderConfig
    )
    events: EventsClientConfig | None = None
    enable_docs: bool = False
    disable_creation: bool = False
