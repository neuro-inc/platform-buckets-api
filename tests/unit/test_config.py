from typing import Any, Dict

from yarl import URL

from platform_buckets_api.config import (
    AWSProviderConfig,
    Config,
    CORSConfig,
    PlatformAuthConfig,
    SentryConfig,
    ServerConfig,
    ZipkinConfig,
)
from platform_buckets_api.config_factory import EnvironConfigFactory


def test_create() -> None:
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
        "NP_AWS_ACCESS_KEY_SECRET": "key-secret",
        "NP_AWS_REGION_NAME": "us-east-2",
    }
    config = EnvironConfigFactory(environ).create()
    assert config == Config(
        server=ServerConfig(host="0.0.0.0", port=8080),
        platform_auth=PlatformAuthConfig(
            url=URL("http://platformauthapi/api/v1"), token="platform-auth-token"
        ),
        cors=CORSConfig(["https://domain1.com", "http://do.main"]),
        zipkin=ZipkinConfig(url=URL("http://zipkin:9411")),
        sentry=SentryConfig(dsn=URL("https://test.com"), cluster_name="test"),
        enable_docs=True,
        cluster_name="test-cluster",
        bucket_provider=AWSProviderConfig(
            access_key_id="key-id",
            access_key_secret="key-secret",
            region_name="us-east-2",
        ),
    )
