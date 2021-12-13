import asyncio
import json
import logging
from contextlib import AsyncExitStack, asynccontextmanager
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    List,
    Mapping,
    Optional,
)

import aiobotocore.session
import aiohttp
import aiohttp.web
import aiohttp_cors
import googleapiclient.discovery
from aiohttp.web import (
    HTTPBadRequest,
    HTTPInternalServerError,
    Request,
    Response,
    StreamResponse,
    json_response,
    middleware,
)
from aiohttp.web_exceptions import (
    HTTPConflict,
    HTTPCreated,
    HTTPNoContent,
    HTTPNotFound,
    HTTPOk,
    HTTPUnprocessableEntity,
)
from aiohttp_apispec import (
    docs,
    querystring_schema,
    request_schema,
    response_schema,
    setup_aiohttp_apispec,
)
from aiohttp_security import check_authorized
from aiohttp_security.api import AUTZ_KEY
from azure.storage.blob.aio import BlobServiceClient
from google.cloud.iam_credentials_v1 import IAMCredentialsAsyncClient
from google.cloud.storage import Client as GCSClient
from marshmallow import Schema, fields
from neuro_auth_client import AuthClient, Permission, User
from neuro_auth_client.security import AuthScheme, setup_security
from neuro_logging import (
    init_logging,
    make_sentry_trace_config,
    make_zipkin_trace_config,
    notrace,
    setup_sentry,
    setup_zipkin_tracer,
)

from .config import (
    AWSProviderConfig,
    AzureProviderConfig,
    Config,
    CORSConfig,
    EMCECSProviderConfig,
    GCPProviderConfig,
    KubeConfig,
    MinioProviderConfig,
    OpenStackProviderConfig,
    PlatformAuthConfig,
)
from .config_factory import EnvironConfigFactory
from .identity import untrusted_user
from .kube_client import KubeClient
from .kube_storage import K8SBucketsStorage, K8SCredentialsStorage
from .permissions_service import PermissionsService
from .providers import (
    AWSBucketProvider,
    AzureBucketProvider,
    BMCWrapper,
    BucketProvider,
    GoogleBucketProvider,
    MinioBucketProvider,
    OpenStackBucketProvider,
    OpenStackStorageApi,
)
from .schema import (
    Bucket,
    BucketCredentials,
    ClientErrorSchema,
    ImportBucketRequest,
    PatchBucket,
    PersistentBucketsCredentials,
    PersistentBucketsCredentialsRequest,
    SignedUrl,
    SignedUrlRequest,
)
from .service import BucketsService, PersistentCredentialsService
from .storage import (
    BaseBucket,
    ExistsError,
    ImportedBucket,
    NotExistsError,
    PersistentCredentials,
    UserBucket,
)
from .utils import ndjson_error_handler


logger = logging.getLogger(__name__)


def accepts_ndjson(request: aiohttp.web.Request) -> bool:
    accept = request.headers.get("Accept", "")
    return "application/x-ndjson" in accept


def _permission_to_primitive(perm: Permission) -> Dict[str, str]:
    return {"uri": perm.uri, "action": perm.action}


async def _get_untrusted_user(request: Request) -> User:
    identity = await untrusted_user(request)
    return User(name=identity.name)


async def check_any_permissions(
    request: aiohttp.web.Request, permissions: List[Permission]
) -> None:
    user_name = await check_authorized(request)
    auth_policy = request.config_dict.get(AUTZ_KEY)
    if not auth_policy:
        raise RuntimeError("Auth policy not configured")

    try:
        missing = await auth_policy.get_missing_permissions(user_name, permissions)
    except aiohttp.ClientError as e:
        # re-wrap in order not to expose the client
        raise RuntimeError(e) from e

    if len(missing) >= len(permissions):
        payload = {"missing": [_permission_to_primitive(p) for p in missing]}
        raise aiohttp.web.HTTPForbidden(
            text=json.dumps(payload), content_type="application/json"
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
                aiohttp.web.post("/import/external", self.import_bucket),
                aiohttp.web.get("", self.list_buckets),
                aiohttp.web.get("/{bucket_id_or_name}", self.get_bucket),
                aiohttp.web.post(
                    "/{bucket_id_or_name}/make_tmp_credentials",
                    self.make_tmp_credentials,
                ),
                aiohttp.web.post(
                    "/{bucket_id_or_name}/sign_blob_url", self.sign_blob_url
                ),
                aiohttp.web.patch("/{bucket_id_or_name}", self.patch_bucket),
                aiohttp.web.delete("/{bucket_id_or_name}", self.delete_bucket),
            ]
        )

    @property
    def service(self) -> BucketsService:
        return self._app["service"]

    @property
    def permissions_service(self) -> PermissionsService:
        return self._app["permissions_service"]

    @property
    def disable_creation(self) -> bool:
        return self._app["disable_creation"]

    async def _resolve_bucket(self, request: Request) -> BaseBucket:
        id_or_name = request.match_info["bucket_id_or_name"]
        try:
            bucket = await self.service.get_bucket(id_or_name)
        except NotExistsError:
            owner_qv = request.query.get("owner")
            user = await _get_untrusted_user(request)
            try:
                bucket = await self.service.get_bucket_by_name(
                    id_or_name, owner_qv or user.name
                )
            except NotExistsError:
                raise HTTPNotFound(text=f"Bucket {id_or_name} not found")
        return bucket

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
            HTTPUnprocessableEntity.status_code: {
                "description": "Bucket creation is disabled",
                "schema": ClientErrorSchema(),
            },
        },
    )
    @request_schema(
        Bucket(partial=["provider", "owner", "created_at", "imported", "public"])
    )
    async def create_bucket(
        self,
        request: aiohttp.web.Request,
    ) -> aiohttp.web.Response:
        user = await _get_untrusted_user(request)
        schema = Bucket(
            partial=["provider", "owner", "created_at", "imported", "public"]
        )
        data = schema.load(await request.json())
        org_name = data.get("org_name")

        await check_any_permissions(
            request, self.permissions_service.get_create_bucket_perms(user, org_name)
        )
        if self.disable_creation:
            return json_response(
                {
                    "code": "disabled",
                    "description": (
                        "Bucket creation is disabled, please use import instead"
                    ),
                },
                status=HTTPUnprocessableEntity.status_code,
            )
        try:
            bucket = await self.service.create_bucket(
                owner=user.name,
                name=data.get("name"),
                org_name=org_name,
            )
        except ExistsError:
            return json_response(
                {
                    "code": "unique",
                    "description": "Bucket with given name exists",
                },
                status=HTTPConflict.status_code,
            )
        return aiohttp.web.json_response(
            data=Bucket().dump(bucket),
            status=HTTPCreated.status_code,
        )

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
    @request_schema(ImportBucketRequest())
    async def import_bucket(
        self,
        request: aiohttp.web.Request,
    ) -> aiohttp.web.Response:
        user = await _get_untrusted_user(request)

        schema = ImportBucketRequest()
        data = schema.load(await request.json())
        org_name = data.get("org_name")
        await check_any_permissions(
            request, self.permissions_service.get_create_bucket_perms(user, org_name)
        )
        try:
            bucket = await self.service.import_bucket(
                owner=user.name,
                provider_type=data["provider"],
                provider_bucket_name=data["provider_bucket_name"],
                credentials=data["credentials"],
                name=data.get("name"),
                org_name=org_name,
            )
        except ExistsError:
            return json_response(
                {
                    "code": "unique",
                    "description": "Bucket with given name exists",
                },
                status=HTTPConflict.status_code,
            )
        return aiohttp.web.json_response(
            data=Bucket().dump(bucket),
            status=HTTPCreated.status_code,
        )

    @docs(
        tags=["buckets"],
        summary="Get bucket by id or name",
        responses={
            HTTPOk.status_code: {
                "description": "Bucket found",
                "schema": Bucket(),
            },
            HTTPNotFound.status_code: {
                "description": "Was unable to found bucket with such id or name",
            },
        },
    )
    @querystring_schema(Schema.from_dict({"owner": fields.String(required=False)}))
    async def get_bucket(
        self,
        request: aiohttp.web.Request,
    ) -> aiohttp.web.Response:
        bucket = await self._resolve_bucket(request)
        await check_any_permissions(
            request, self.permissions_service.get_bucket_read_perms(bucket)
        )
        return aiohttp.web.json_response(
            data=Bucket().dump(bucket),
            status=HTTPOk.status_code,
        )

    @docs(
        tags=["buckets"],
        summary="List all buckets available to current user",
    )
    @response_schema(Bucket(many=True), 200)
    async def list_buckets(
        self,
        request: aiohttp.web.Request,
    ) -> aiohttp.web.StreamResponse:
        username = await check_authorized(request)
        async with self.service.get_user_buckets(owner=username) as buckets_it:
            if accepts_ndjson(request):
                response = aiohttp.web.StreamResponse()
                response.headers["Content-Type"] = "application/x-ndjson"
                await response.prepare(request)
                async with ndjson_error_handler(request, response):
                    async for bucket in buckets_it:
                        payload_line = Bucket().dumps(bucket)
                        await response.write(payload_line.encode() + b"\n")
                return response
            else:
                response_payload = [
                    Bucket().dump(bucket) async for bucket in buckets_it
                ]
                return aiohttp.web.json_response(
                    data=response_payload, status=HTTPOk.status_code
                )

    @docs(
        tags=["buckets"],
        summary="Delete bucket by id or name",
        responses={
            HTTPNoContent.status_code: {
                "description": "Bucket deleted",
            },
            HTTPNotFound.status_code: {
                "description": "Was unable to found bucket with such id or name",
            },
        },
    )
    @querystring_schema(Schema.from_dict({"owner": fields.String(required=False)}))
    async def delete_bucket(
        self,
        request: aiohttp.web.Request,
    ) -> aiohttp.web.Response:
        bucket = await self._resolve_bucket(request)
        await check_any_permissions(
            request, self.permissions_service.get_bucket_write_perms(bucket)
        )
        await self.service.delete_bucket(bucket.id)
        raise HTTPNoContent

    @docs(
        tags=["buckets"],
        summary="Update bucket by id or name",
        responses={
            HTTPNoContent.status_code: {
                "description": "Bucket updated",
                "schema": Bucket(),
            },
            HTTPNotFound.status_code: {
                "description": "Was unable to found bucket with such id or name",
            },
        },
    )
    @querystring_schema(Schema.from_dict({"owner": fields.String(required=False)}))
    @request_schema(PatchBucket())
    async def patch_bucket(
        self,
        request: aiohttp.web.Request,
    ) -> aiohttp.web.Response:
        data = PatchBucket().load(await request.json())
        bucket = await self._resolve_bucket(request)
        await check_any_permissions(
            request, self.permissions_service.get_bucket_write_perms(bucket)
        )
        if "public" in data and data["public"] != bucket.public:
            bucket = await self.service.set_public_access(bucket, data["public"])
        return aiohttp.web.json_response(
            data=Bucket().dump(bucket),
            status=HTTPOk.status_code,
        )

    @docs(
        tags=["buckets"],
        summary="Get bucket temporarily credentials",
        responses={
            HTTPOk.status_code: {
                "description": "Bucket temporarily credentials was created",
                "schema": BucketCredentials(),
            },
            HTTPNotFound.status_code: {
                "description": "Was unable to found bucket with such id or name",
            },
        },
    )
    @querystring_schema(Schema.from_dict({"owner": fields.String(required=False)}))
    async def make_tmp_credentials(
        self,
        request: aiohttp.web.Request,
    ) -> aiohttp.web.Response:
        bucket = await self._resolve_bucket(request)
        await check_any_permissions(
            request, self.permissions_service.get_bucket_read_perms(bucket)
        )
        user = await _get_untrusted_user(request)
        checker = await self.permissions_service.get_perms_checker(user.name)
        if isinstance(bucket, UserBucket):
            credentials = await self.service.make_tmp_credentials(
                bucket,
                write=checker.can_write(bucket),
                requester=user.name,
            )
        elif isinstance(bucket, ImportedBucket):
            credentials = bucket.credentials
        else:
            assert False, "unreachable"
        return aiohttp.web.json_response(
            data={
                "bucket_id": bucket.id,
                "provider": bucket.provider_bucket.provider_type,
                "read_only": not checker.can_write(bucket),
                "credentials": {
                    "bucket_name": bucket.provider_bucket.name,
                    **credentials,
                },
            },
            status=HTTPOk.status_code,
        )

    @docs(
        tags=["buckets"],
        summary="Get signed url for blob inside bucket",
        responses={
            HTTPOk.status_code: {
                "description": "Signed url was generated ",
                "schema": SignedUrl(),
            },
            HTTPNotFound.status_code: {
                "description": "Was unable to found bucket with such id or name",
            },
        },
    )
    @request_schema(SignedUrlRequest())
    @querystring_schema(Schema.from_dict({"owner": fields.String(required=False)}))
    async def sign_blob_url(
        self,
        request: aiohttp.web.Request,
    ) -> aiohttp.web.Response:
        bucket = await self._resolve_bucket(request)
        await check_any_permissions(
            request, self.permissions_service.get_bucket_read_perms(bucket)
        )
        schema = SignedUrlRequest()
        data = schema.load(await request.json())
        url = await self.service.sign_url_for_blob(
            bucket, data["key"], data["expires_in_sec"]
        )
        return aiohttp.web.json_response(
            data={"url": str(url)},
            status=HTTPOk.status_code,
        )


class PersistentCredentialsApiHandler:
    def __init__(self, app: aiohttp.web.Application, config: Config) -> None:
        self._app = app
        self._config = config

    def register(self, app: aiohttp.web.Application) -> None:
        app.add_routes(
            [
                aiohttp.web.post("", self.create_credentials),
                aiohttp.web.get("", self.list_credentials),
                aiohttp.web.get("/{credential_id_or_name}", self.get_credentials),
                aiohttp.web.delete("/{credential_id_or_name}", self.delete_credentials),
            ]
        )

    @property
    def buckets_service(self) -> BucketsService:
        return self._app["buckets_service"]

    @property
    def credentials_service(self) -> PersistentCredentialsService:
        return self._app["credentials_service"]

    @property
    def permissions_service(self) -> PermissionsService:
        return self._app["permissions_service"]

    @property
    def disable_creation(self) -> bool:
        return self._app["disable_creation"]

    async def _resolve_credentials(self, request: Request) -> PersistentCredentials:
        id_or_name = request.match_info["credential_id_or_name"]
        try:
            credentials = await self.credentials_service.get_credentials(id_or_name)
        except NotExistsError:
            user = await _get_untrusted_user(request)
            try:
                credentials = await self.credentials_service.get_credentials_by_name(
                    id_or_name, user.name
                )
            except NotExistsError:
                raise HTTPNotFound(text=f"PersistentCredentials {id_or_name} not found")
        username = await check_authorized(request)
        if username != credentials.owner:
            raise HTTPNotFound(text=f"PersistentCredentials {id_or_name} not found")
        return credentials

    async def _serialize_credentials(
        self, credentials: PersistentCredentials
    ) -> Mapping[str, Any]:
        buckets = [
            await self.buckets_service.get_bucket(bucket_id)
            for bucket_id in credentials.bucket_ids
        ]
        return {
            "id": credentials.id,
            "name": credentials.name,
            "owner": credentials.owner,
            "read_only": credentials.read_only,
            "credentials": [
                {
                    "bucket_id": bucket.id,
                    "provider": bucket.provider_bucket.provider_type,
                    "read_only": credentials.read_only,
                    "credentials": {
                        "bucket_name": bucket.provider_bucket.name,
                        **credentials.role.credentials,
                    },
                }
                for bucket in buckets
            ],
        }

    @docs(
        tags=["credentials"],
        summary="Create persistent bucket credentials",
        responses={
            HTTPCreated.status_code: {
                "description": "Credentials created",
                "schema": PersistentBucketsCredentials(),
            },
            HTTPConflict.status_code: {
                "description": "Credentials with such name exists",
                "schema": ClientErrorSchema(),
            },
            HTTPUnprocessableEntity.status_code: {
                "description": "Credentials creation is disabled",
                "schema": ClientErrorSchema(),
            },
        },
    )
    @request_schema(PersistentBucketsCredentialsRequest())
    async def create_credentials(
        self,
        request: aiohttp.web.Request,
    ) -> aiohttp.web.Response:
        username = await check_authorized(request)
        if self.disable_creation:
            return json_response(
                {
                    "code": "disabled",
                    "description": "Credentials creation is disabled.",
                },
                status=HTTPUnprocessableEntity.status_code,
            )
        schema = PersistentBucketsCredentialsRequest()
        data = schema.load(await request.json())
        for bucket_id in data["bucket_ids"]:
            bucket = await self.buckets_service.get_bucket(bucket_id)
            if data["read_only"]:
                await check_any_permissions(
                    request, self.permissions_service.get_bucket_read_perms(bucket)
                )
            else:
                await check_any_permissions(
                    request, self.permissions_service.get_bucket_write_perms(bucket)
                )
            if bucket.imported:
                raise ValueError(
                    "Cannot create credential for imported "
                    f"bucket {bucket.name or bucket.id}"
                )
        credentials = await self.credentials_service.create_credentials(
            name=data.get("name"),
            bucket_ids=data["bucket_ids"],
            owner=username,
            read_only=data["read_only"],
        )
        return aiohttp.web.json_response(
            data=await self._serialize_credentials(credentials),
            status=HTTPCreated.status_code,
        )

    @docs(
        tags=["credentials"],
        summary="Get credentials by id or name",
        responses={
            HTTPOk.status_code: {
                "description": "Credentials found",
                "schema": PersistentBucketsCredentials(),
            },
            HTTPNotFound.status_code: {
                "description": "Was unable to found bucket with such id or name",
            },
        },
    )
    async def get_credentials(
        self,
        request: aiohttp.web.Request,
    ) -> aiohttp.web.Response:
        credentials = await self._resolve_credentials(request)
        return aiohttp.web.json_response(
            data=await self._serialize_credentials(credentials),
            status=HTTPOk.status_code,
        )

    @docs(
        tags=["credentials"],
        summary="List all persistent credentials available to current user",
    )
    @response_schema(PersistentBucketsCredentials(many=True), 200)
    async def list_credentials(
        self,
        request: aiohttp.web.Request,
    ) -> aiohttp.web.StreamResponse:
        username = await check_authorized(request)
        async with self.credentials_service.list_user_credentials(
            owner=username
        ) as credentials_it:
            if accepts_ndjson(request):
                response = aiohttp.web.StreamResponse()
                response.headers["Content-Type"] = "application/x-ndjson"
                await response.prepare(request)
                async with ndjson_error_handler(request, response):
                    async for credentials in credentials_it:
                        payload_line = json.dumps(
                            await self._serialize_credentials(credentials)
                        )
                        await response.write(payload_line.encode() + b"\n")
                return response
            else:
                response_payload = [
                    await self._serialize_credentials(credentials)
                    async for credentials in credentials_it
                ]
                return aiohttp.web.json_response(
                    data=response_payload, status=HTTPOk.status_code
                )

    @docs(
        tags=["credentials"],
        summary="Delete persistent credentials by id or name",
        responses={
            HTTPNoContent.status_code: {
                "description": "Credentials deleted",
            },
            HTTPNotFound.status_code: {
                "description": "Was unable to found credentials with such id or name",
            },
        },
    )
    async def delete_credentials(
        self,
        request: aiohttp.web.Request,
    ) -> aiohttp.web.Response:
        credentials = await self._resolve_credentials(request)
        await self.credentials_service.delete_credentials(credentials.id)
        raise HTTPNoContent


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


async def create_persistent_credentials_app(config: Config) -> aiohttp.web.Application:
    app = aiohttp.web.Application()
    handler = PersistentCredentialsApiHandler(app, config)
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


@asynccontextmanager
async def make_gcs_client(config: GCPProviderConfig) -> AsyncIterator[GCSClient]:
    client = GCSClient(
        project=config.key_json["project_id"],
        credentials=config.sa_credentials,
    )
    yield client
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, client.close)


@asynccontextmanager
async def make_google_iam_client(config: GCPProviderConfig) -> AsyncIterator[Any]:
    iam = googleapiclient.discovery.build(
        "iam", "v1", credentials=config.sa_credentials
    )
    yield iam
    iam.close()


@asynccontextmanager
async def make_google_iam_client_2(config: GCPProviderConfig) -> AsyncIterator[Any]:
    iam_2 = IAMCredentialsAsyncClient(credentials=config.sa_credentials)
    yield iam_2


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
        allow_methods="*",
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
                    session = aiobotocore.session.get_session()
                    client_kwargs = dict(
                        region_name=config.bucket_provider.region_name,
                        aws_secret_access_key=config.bucket_provider.secret_access_key,
                        aws_access_key_id=config.bucket_provider.access_key_id,
                    )
                    if config.bucket_provider.endpoint_url:
                        client_kwargs["endpoint_url"] = str(
                            config.bucket_provider.endpoint_url
                        )
                    s3_client = await exit_stack.enter_async_context(
                        session.create_client("s3", **client_kwargs)
                    )
                    iam_client = await exit_stack.enter_async_context(
                        session.create_client("iam", **client_kwargs)
                    )
                    sts_client = await exit_stack.enter_async_context(
                        session.create_client("sts", **client_kwargs)
                    )
                    bucket_provider = AWSBucketProvider(
                        s3_client=s3_client,
                        iam_client=iam_client,
                        sts_client=sts_client,
                        s3_role_arn=config.bucket_provider.s3_role_arn,
                    )
                elif isinstance(config.bucket_provider, MinioProviderConfig):
                    session = aiobotocore.session.get_session()
                    client_kwargs = dict(
                        region_name=config.bucket_provider.region_name,
                        aws_secret_access_key=config.bucket_provider.secret_access_key,
                        aws_access_key_id=config.bucket_provider.access_key_id,
                        endpoint_url=str(config.bucket_provider.endpoint_url),
                    )
                    s3_client = await exit_stack.enter_async_context(
                        session.create_client("s3", **client_kwargs)
                    )
                    sts_client = await exit_stack.enter_async_context(
                        session.create_client("sts", **client_kwargs)
                    )
                    bmc_wrapper = await exit_stack.enter_async_context(
                        BMCWrapper(
                            url=config.bucket_provider.endpoint_url,
                            username=config.bucket_provider.access_key_id,
                            password=config.bucket_provider.secret_access_key,
                        )
                    )
                    bucket_provider = MinioBucketProvider(
                        s3_client=s3_client,
                        sts_client=sts_client,
                        mc=bmc_wrapper,
                        public_url=config.bucket_provider.endpoint_public_url,
                    )
                elif isinstance(config.bucket_provider, AzureProviderConfig):
                    blob_client = await exit_stack.enter_async_context(
                        BlobServiceClient(
                            account_url=str(config.bucket_provider.endpoint_url),
                            credential=config.bucket_provider.credential,
                        )
                    )
                    bucket_provider = AzureBucketProvider(
                        blob_client=blob_client,
                        storage_endpoint=str(config.bucket_provider.endpoint_url),
                    )
                elif isinstance(config.bucket_provider, GCPProviderConfig):
                    gcs_client = await exit_stack.enter_async_context(
                        make_gcs_client(config.bucket_provider)
                    )
                    iam_client = await exit_stack.enter_async_context(
                        make_google_iam_client(config.bucket_provider)
                    )
                    iam_client_2 = await exit_stack.enter_async_context(
                        make_google_iam_client_2(config.bucket_provider)
                    )
                    bucket_provider = GoogleBucketProvider(
                        gcs_client=gcs_client,
                        iam_client=iam_client,
                        iam_client_2=iam_client_2,
                    )
                elif isinstance(config.bucket_provider, EMCECSProviderConfig):
                    session = aiobotocore.session.get_session()
                    client_kwargs = dict(
                        aws_secret_access_key=config.bucket_provider.secret_access_key,
                        aws_access_key_id=config.bucket_provider.access_key_id,
                        # This "region" value is ignored by EMC ECS,
                        # but required by botocore
                        region_name="any",
                    )
                    s3_client = await exit_stack.enter_async_context(
                        session.create_client(
                            "s3",
                            endpoint_url=str(config.bucket_provider.s3_endpoint_url),
                            **client_kwargs,
                        )
                    )
                    iam_client = await exit_stack.enter_async_context(
                        session.create_client(
                            "iam",
                            endpoint_url=str(
                                config.bucket_provider.management_endpoint_url / "iam"
                            ),
                            **client_kwargs,
                        )
                    )
                    sts_client = await exit_stack.enter_async_context(
                        session.create_client(
                            "sts",
                            endpoint_url=str(
                                config.bucket_provider.management_endpoint_url / "sts"
                            ),
                            **client_kwargs,
                        )
                    )
                    bucket_provider = AWSBucketProvider(
                        s3_client=s3_client,
                        iam_client=iam_client,
                        sts_client=sts_client,
                        s3_role_arn=config.bucket_provider.s3_role_urn,
                        permissions_boundary="urn:ecs:iam:::policy/ECSS3FullAccess",
                    )
                elif isinstance(config.bucket_provider, OpenStackProviderConfig):
                    os_api = OpenStackStorageApi(
                        account_id=config.bucket_provider.account_id,
                        password=config.bucket_provider.password,
                        url=config.bucket_provider.endpoint_url,
                    )
                    bucket_provider = OpenStackBucketProvider(
                        api=os_api,
                        region_name=config.bucket_provider.region_name,
                        s3_url=config.bucket_provider.s3_endpoint_url,
                    )
                else:
                    raise Exception(
                        f"Unknown bucket provider {type(config.bucket_provider)}"
                    )

            logger.info("Initializing Kubernetes client")
            kube_client = await exit_stack.enter_async_context(
                create_kube_client(config.kube, make_tracing_trace_configs(config))
            )

            logger.info("Initializing PermissionsService")
            permissions_service = PermissionsService(
                auth_client=auth_client,
                cluster_name=config.cluster_name,
            )
            app["buckets_app"]["permissions_service"] = permissions_service
            app["credentials_app"]["permissions_service"] = permissions_service

            logger.info("Initializing BucketsService")
            buckets_service = BucketsService(
                storage=K8SBucketsStorage(kube_client),
                bucket_provider=bucket_provider,
                permissions_service=permissions_service,
            )
            app["buckets_app"]["service"] = buckets_service
            app["buckets_app"]["disable_creation"] = config.disable_creation

            logger.info("Initializing PersistentCredentialsService")
            credentials_service = PersistentCredentialsService(
                storage=K8SCredentialsStorage(kube_client),
                bucket_provider=bucket_provider,
                buckets_service=buckets_service,
            )
            app["credentials_app"]["buckets_service"] = buckets_service
            app["credentials_app"]["credentials_service"] = credentials_service
            app["credentials_app"]["disable_creation"] = config.disable_creation

            yield

    app.cleanup_ctx.append(_init_app)

    api_v1_app = await create_api_v1_app()
    app["api_v1_app"] = api_v1_app

    buckets_app = await create_buckets_app(config)
    app["buckets_app"] = buckets_app
    api_v1_app.add_subapp("/buckets/buckets", buckets_app)

    credentials_app = await create_persistent_credentials_app(config)
    app["credentials_app"] = credentials_app
    api_v1_app.add_subapp("/buckets/persistent_credentials", credentials_app)

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
