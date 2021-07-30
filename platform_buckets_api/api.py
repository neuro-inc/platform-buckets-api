import logging
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, Awaitable, Callable, List, Mapping, Optional

import aiobotocore
import aiohttp
import aiohttp.web
import aiohttp_cors
from aiohttp.web import (
    HTTPBadRequest,
    HTTPInternalServerError,
    Request,
    Response,
    StreamResponse,
    json_response,
    middleware,
)
from aiohttp.web_exceptions import HTTPConflict, HTTPCreated
from aiohttp_apispec import docs, request_schema, setup_aiohttp_apispec
from aiohttp_security import check_authorized
from neuro_auth_client import AuthClient
from neuro_auth_client.security import AuthScheme, setup_security
from platform_logging import (
    init_logging,
    make_sentry_trace_config,
    make_zipkin_trace_config,
    notrace,
    setup_sentry,
    setup_zipkin_tracer,
)

from .config import (
    AWSProviderConfig,
    BucketsProviderType,
    Config,
    CORSConfig,
    KubeConfig,
    PlatformAuthConfig,
)
from .config_factory import EnvironConfigFactory
from .kube_client import KubeClient
from .kube_storage import K8SStorage
from .providers import AWSBucketProvider, BucketProvider
from .schema import Bucket, ClientErrorSchema
from .service import Service
from .storage import UserBucket, UserCredentials


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResponseBucket:
    name: str
    owner: str
    provider: BucketsProviderType
    credentials: Mapping[str, str]

    @classmethod
    def from_user_bucket(
        cls, user_bucket: UserBucket, credentials: UserCredentials
    ) -> "ResponseBucket":
        return cls(
            name=user_bucket.name,
            owner=user_bucket.owner,
            provider=user_bucket.provider_bucket.provider_type,
            credentials={
                "bucket_name": user_bucket.provider_bucket.name,
                **credentials.role.credentials,
            },
        )


class ApiHandler:
    def register(self, app: aiohttp.web.Application) -> None:
        app.add_routes(
            [
                aiohttp.web.get("/ping", self.handle_ping),
                aiohttp.web.get("/secured-ping", self.handle_secured_ping),
            ]
        )

    @notrace
    async def handle_ping(self, request: Request) -> Response:
        return Response(text="Pong")

    @notrace
    async def handle_secured_ping(self, request: Request) -> Response:
        await check_authorized(request)
        return Response(text="Secured Pong")


class BucketsApiHandler:
    def __init__(self, app: aiohttp.web.Application, config: Config) -> None:
        self._app = app
        self._config = config

    def register(self, app: aiohttp.web.Application) -> None:
        app.add_routes(
            [
                aiohttp.web.post("", self.create_bucket),
            ]
        )

    @property
    def service(self) -> Service:
        return self._app["service"]

    @docs(
        tags=["buckets"],
        summary="Create bucket",
        responses={
            HTTPCreated.status_code: {
                "description": "Bucket created",
                "schema": Bucket(),
            },
            HTTPConflict.status_code: {
                "description": "Bucket with such name exists",
                "schema": ClientErrorSchema(),
            },
        },
    )
    @request_schema(Bucket(partial=["provider", "owner", "credentials"]))
    async def create_bucket(
        self,
        request: aiohttp.web.Request,
    ) -> aiohttp.web.Response:
        username = await check_authorized(request)
        schema = Bucket(partial=["provider", "owner", "credentials"])
        data = schema.load(await request.json())
        bucket, credentials = await self.service.create_bucket(
            name=data["name"],
            owner=username,
        )
        return aiohttp.web.json_response(
            data=Bucket().dump(ResponseBucket.from_user_bucket(bucket, credentials)),
            status=HTTPCreated.status_code,
        )


@middleware
async def handle_exceptions(
    request: Request, handler: Callable[[Request], Awaitable[StreamResponse]]
) -> StreamResponse:
    try:
        return await handler(request)
    except ValueError as e:
        payload = {"error": str(e)}
        return json_response(payload, status=HTTPBadRequest.status_code)
    except aiohttp.web.HTTPException:
        raise
    except Exception as e:
        msg_str = f"Unexpected exception: {str(e)}. Path with query: {request.path_qs}."
        logging.exception(msg_str)
        payload = {"error": msg_str}
        return json_response(payload, status=HTTPInternalServerError.status_code)


async def create_api_v1_app() -> aiohttp.web.Application:
    api_v1_app = aiohttp.web.Application()
    api_v1_handler = ApiHandler()
    api_v1_handler.register(api_v1_app)
    return api_v1_app


async def create_buckets_app(config: Config) -> aiohttp.web.Application:
    app = aiohttp.web.Application()
    handler = BucketsApiHandler(app, config)
    handler.register(app)
    return app


@asynccontextmanager
async def create_auth_client(config: PlatformAuthConfig) -> AsyncIterator[AuthClient]:
    async with AuthClient(config.url, config.token) as client:
        yield client


@asynccontextmanager
async def create_kube_client(
    config: KubeConfig, trace_configs: Optional[List[aiohttp.TraceConfig]] = None
) -> AsyncIterator[KubeClient]:
    client = KubeClient(
        base_url=config.endpoint_url,
        namespace=config.namespace,
        cert_authority_path=config.cert_authority_path,
        cert_authority_data_pem=config.cert_authority_data_pem,
        auth_type=config.auth_type,
        auth_cert_path=config.auth_cert_path,
        auth_cert_key_path=config.auth_cert_key_path,
        token=config.token,
        token_path=None,  # TODO (A Yushkovskiy) add support for token_path or drop
        conn_timeout_s=config.client_conn_timeout_s,
        read_timeout_s=config.client_read_timeout_s,
        watch_timeout_s=config.client_watch_timeout_s,
        conn_pool_size=config.client_conn_pool_size,
        trace_configs=trace_configs,
    )
    try:
        await client.init()
        yield client
    finally:
        await client.close()


def make_tracing_trace_configs(config: Config) -> List[aiohttp.TraceConfig]:
    trace_configs = []

    if config.zipkin:
        trace_configs.append(make_zipkin_trace_config())

    if config.sentry:
        trace_configs.append(make_sentry_trace_config())

    return trace_configs


def _setup_cors(app: aiohttp.web.Application, config: CORSConfig) -> None:
    if not config.allowed_origins:
        return

    logger.info(f"Setting up CORS with allowed origins: {config.allowed_origins}")
    default_options = aiohttp_cors.ResourceOptions(
        allow_credentials=True,
        expose_headers="*",
        allow_headers="*",
    )
    cors = aiohttp_cors.setup(
        app, defaults={origin: default_options for origin in config.allowed_origins}
    )
    for route in app.router.routes():
        logger.debug(f"Setting up CORS for {route}")
        cors.add(route)


async def create_app(
    config: Config, _bucket_provider: Optional[BucketProvider] = None
) -> aiohttp.web.Application:
    app = aiohttp.web.Application(middlewares=[handle_exceptions])
    app["config"] = config

    async def _init_app(app: aiohttp.web.Application) -> AsyncIterator[None]:
        async with AsyncExitStack() as exit_stack:
            logger.info("Initializing Auth client")
            auth_client = await exit_stack.enter_async_context(
                create_auth_client(config.platform_auth)
            )

            await setup_security(
                app=app, auth_client=auth_client, auth_scheme=AuthScheme.BEARER
            )
            if _bucket_provider is not None:
                bucket_provider = _bucket_provider
            if _bucket_provider is None:
                if isinstance(config.bucket_provider, AWSProviderConfig):
                    session = aiobotocore.get_session()
                    client_kwargs = dict(
                        region_name=config.bucket_provider.region_name,
                        aws_secret_access_key=config.bucket_provider.secret_access_key,
                        aws_access_key_id=config.bucket_provider.access_key_id,
                    )
                    if config.bucket_provider.endpoint_url:
                        client_kwargs[
                            "endpoint_url"
                        ] = config.bucket_provider.endpoint_url
                    s3_client = await exit_stack.enter_async_context(
                        session.create_client("s3", **client_kwargs)
                    )
                    iam_client = await exit_stack.enter_async_context(
                        session.create_client("iam", **client_kwargs)
                    )
                    bucket_provider = AWSBucketProvider(
                        s3_client=s3_client,
                        iam_client=iam_client,
                    )
                else:
                    raise Exception(
                        f"Unknown bucket provider {type(config.bucket_provider)}"
                    )

            logger.info("Initializing Kubernetes client")
            kube_client = await exit_stack.enter_async_context(
                create_kube_client(config.kube, make_tracing_trace_configs(config))
            )

            logger.info("Initializing Service")
            app["buckets_app"]["service"] = Service(
                storage=K8SStorage(kube_client),
                auth_client=auth_client,
                bucket_provider=bucket_provider,
                cluster_name=config.cluster_name,
            )

            yield

    app.cleanup_ctx.append(_init_app)

    api_v1_app = await create_api_v1_app()
    app["api_v1_app"] = api_v1_app

    buckets_app = await create_buckets_app(config)
    app["buckets_app"] = buckets_app
    api_v1_app.add_subapp("/buckets", buckets_app)

    app.add_subapp("/api/v1", api_v1_app)

    _setup_cors(app, config.cors)
    if config.enable_docs:
        prefix = "/api/docs/v1/buckets"
        setup_aiohttp_apispec(
            app=app,
            title="Buckets API documentation",
            version="v1",
            url=f"{prefix}/swagger.json",
            static_path=f"{prefix}/static",
            swagger_path=f"{prefix}/ui",
            security=[{"jwt": []}],
            securityDefinitions={
                "jwt": {"type": "apiKey", "name": "Authorization", "in": "header"},
            },
        )
    return app


def setup_tracing(config: Config) -> None:
    if config.zipkin:
        setup_zipkin_tracer(
            config.zipkin.app_name,
            config.server.host,
            config.server.port,
            config.zipkin.url,
            config.zipkin.sample_rate,
        )

    if config.sentry:
        setup_sentry(
            config.sentry.dsn,
            app_name=config.sentry.app_name,
            cluster_name=config.sentry.cluster_name,
            sample_rate=config.sentry.sample_rate,
        )


def main() -> None:  # pragma: no coverage
    init_logging()
    config = EnvironConfigFactory().create()
    logging.info("Loaded config: %r", config)
    setup_tracing(config)
    aiohttp.web.run_app(
        create_app(config),
        host=config.server.host,
        port=config.server.port,
    )
