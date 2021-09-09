import functools
from typing import Any, Callable, Optional, TypeVar

import aiohttp.web
from aiohttp_apispec import querystring_schema
from marshmallow import Schema, fields, validate

from platform_buckets_api.config import BucketsProviderType


F = TypeVar("F", bound=Callable[..., Any])


def query_schema(**kwargs: fields.Field) -> Callable[[F], F]:
    schema: Schema = Schema.from_dict(kwargs)()  # type: ignore

    def _decorator(handler: F) -> F:
        @querystring_schema(schema)
        @functools.wraps(handler)
        async def _wrapped(self: Any, request: aiohttp.web.Request) -> Any:
            query_data = {
                key: request.query.getall(key)
                if len(request.query.getall(key)) > 1
                or isinstance(schema.fields.get(key), fields.List)
                else request.query[key]
                for key in request.query.keys()
            }
            validated = schema.load(query_data)
            return await handler(self, request, **validated)

        return _wrapped

    return _decorator


class ProviderTypeField(fields.String):
    def _deserialize(self, *args: Any, **kwargs: Any) -> BucketsProviderType:
        res: str = super()._deserialize(*args, **kwargs)
        return BucketsProviderType(res)

    def _serialize(
        self, value: Optional[BucketsProviderType], *args: Any, **kwargs: Any
    ) -> Optional[str]:
        if value is None:
            return None
        return super()._serialize(value.value, *args, **kwargs)


class ImportBucketRequest(Schema):
    id = fields.String(required=True, dump_only=True)
    name = fields.String(
        required=False,
        allow_none=True,
        validate=[
            validate.Regexp(r"^[a-z](?:-?[a-z0-9_-])*(?!\n)$"),
            validate.Length(min=3, max=40),
        ],
    )
    provider = ProviderTypeField(
        required=True,
        validate=validate.OneOf(
            choices=[provider_type for provider_type in BucketsProviderType]
        ),
    )
    provider_bucket_name = fields.String(required=True)
    credentials = fields.Dict(required=True)


class Bucket(Schema):
    id = fields.String(required=True, dump_only=True)
    name = fields.String(
        required=False,
        allow_none=True,
        validate=[
            validate.Regexp(r"^[a-z](?:-?[a-z0-9_-])*(?!\n)$"),
            validate.Length(min=3, max=40),
        ],
    )
    owner = fields.String(required=True)
    provider = ProviderTypeField(
        required=True,
        attribute="provider_bucket.provider_type",
        validate=validate.OneOf(
            choices=[provider_type for provider_type in BucketsProviderType]
        ),
    )
    created_at = fields.DateTime(required=True)
    imported = fields.Boolean(required=True)


class BucketCredentials(Schema):
    bucket_id = fields.String(required=True)
    provider = ProviderTypeField(
        required=True,
        validate=validate.OneOf(
            choices=[provider_type for provider_type in BucketsProviderType]
        ),
    )
    credentials = fields.Dict(required=True)


class PersistentBucketsCredentialsRequest(Schema):
    name = fields.String(
        required=False,
        allow_none=True,
        validate=[
            validate.Regexp(r"^[a-z](?:-?[a-z0-9_-])*(?!\n)$"),
            validate.Length(min=3, max=40),
        ],
    )
    bucket_ids = fields.List(fields.String(), required=True)
    read_only = fields.Boolean(required=False, allow_none=True, load_default=False)


class PersistentBucketsCredentials(Schema):
    id = fields.String(required=True, dump_only=True)
    name = fields.String(
        required=False,
        allow_none=True,
        validate=[
            validate.Regexp(r"^[a-z](?:-?[a-z0-9_-])*(?!\n)$"),
            validate.Length(min=3, max=40),
        ],
    )
    owner = fields.String(required=True)
    credentials = fields.List(fields.Nested(BucketCredentials), required=True)
    read_only = fields.Boolean(required=True)


class ClientErrorSchema(Schema):
    code = fields.String(required=True)
    description = fields.String(required=True)


class SignedUrl(Schema):
    url = fields.Url(required=True)
