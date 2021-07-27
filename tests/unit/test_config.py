from typing import Any, Dict

from yarl import URL

from platform_buckets_api.config import (
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
    )
