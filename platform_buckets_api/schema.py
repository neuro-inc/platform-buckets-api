import functools
from typing import Any, Callable, TypeVar

import aiohttp.web
from aiohttp_apispec import querystring_schema
from marshmallow import Schema, fields, validate

from platform_buckets_api.storage import BucketsProviderType


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


class Bucket(Schema):
    name = fields.String(required=True)
    cluster_name = fields.String(required=True)
    owner = fields.String(required=True)
    provider = fields.String(
        required=True,
        validate=validate.OneOf(
            choices=[provider_type for provider_type in BucketsProviderType]
        ),
    )
    credentials = fields.Dict(required=True)


class ClientErrorSchema(Schema):
    code = fields.String(required=True)
    description = fields.String(required=True)
