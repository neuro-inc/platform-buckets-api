from typing import Any

from pydantic import BaseModel, Field

from apolo_app_types.protocols.common.buckets import Bucket


class IdResponse(BaseModel):
    id: str
    value: Bucket


class BasicResponse(BaseModel):
    status: str
    data: dict[str, Any] | list[dict[str, Any]] | None = None


class ListResponse(BaseModel):
    status: str
    data: list[IdResponse] | None = None


class BucketResponse(BaseModel):
    status: str
    data: Bucket | None = None


class FilterParams(BaseModel):
    filter: str | None = None
    limit: int = Field(10, gt=0, le=100)
    offset: int = Field(0, ge=0)
