import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncIterator

import aiohttp.web


@asynccontextmanager
async def ndjson_error_handler(
    request: aiohttp.web.Request,
    response: aiohttp.web.StreamResponse,
) -> AsyncIterator[None]:
    try:
        yield
    except asyncio.CancelledError:
        raise
    except Exception as e:
        msg_str = (
            f"Unexpected exception {e.__class__.__name__}: {str(e)}. "
            f"Path with query: {request.path_qs}."
        )
        logging.exception(msg_str)
        payload = {"error": msg_str}
        await response.write(json.dumps(payload).encode())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def datetime_dump(dt: datetime) -> str:
    return str(dt.timestamp())


def datetime_load(raw: str) -> datetime:
    return datetime.fromtimestamp(float(raw), timezone.utc)
