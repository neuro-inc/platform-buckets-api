import os
from typing import Annotated

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
from src.config import Config
from src.dependencies import DepApoloClient
from src.models import (
    BasicResponse,
    BucketResponse,
    FilterParams,
    IdResponse,
    ListResponse,
)
from src.utils import filter_buckets, get_buckets


class App(FastAPI):
    config: Config


app = App()
app.config = Config(
    cluster_name=os.getenv("CLUSTER_NAME", "default"),
    api_url=os.getenv("API_URL", "https://api.dev.apolo.us"),
    env=os.getenv("ENV", "dev"),
)


@app.get("/")
@app.get("/health")
@app.get("/healthz")
async def root() -> BasicResponse:
    return BasicResponse(status="healthy")


@app.get("/outputs")
async def outputs(
    filter_query: Annotated[FilterParams, Query()], apolo_client: DepApoloClient
) -> ListResponse:
    buckets = await get_buckets(apolo_client)
    buckets = filter_buckets(buckets, filter_query.filter)

    if filter_query.limit:
        buckets = buckets[
            filter_query.offset : filter_query.offset + filter_query.limit
        ]

    return ListResponse(
        status="success",
        data=[IdResponse(id=bucket.id, value=bucket) for bucket in buckets],
    )


@app.get("/outputs/{bucket_id}")
async def get_output(bucket_id: str, apolo_client: DepApoloClient) -> BucketResponse:
    buckets = await get_buckets(apolo_client)
    bucket = next((b for b in buckets if b.id == bucket_id), None)
    if bucket:
        return BucketResponse(status="success", data=bucket)
    return BucketResponse(status="error", data=None)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={"message": "An unexpected error occurred.", "details": str(exc)},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0", port=8000, log_level="info")
