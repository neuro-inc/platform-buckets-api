import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, Optional

import aiohttp
import pytest
from aiohttp.web import HTTPOk
from aiohttp.web_exceptions import (
    HTTPConflict,
    HTTPCreated,
    HTTPForbidden,
    HTTPNoContent,
    HTTPNotFound,
    HTTPUnauthorized,
)
from neuro_auth_client import AuthClient, Permission

from platform_buckets_api.api import create_app
from platform_buckets_api.config import Config
from platform_buckets_api.utils import utc_now

from .auth import _User
from .conftest import ApiAddress, create_local_app_server


pytestmark = pytest.mark.asyncio


@dataclass(frozen=True)
class BucketsApiEndpoints:
    address: ApiAddress

    @property
    def api_v1_endpoint(self) -> str:
        return f"http://{self.address.host}:{self.address.port}/api/v1"

    @property
    def ping_url(self) -> str:
        return f"{self.api_v1_endpoint}/ping"

    @property
    def secured_ping_url(self) -> str:
        return f"{self.api_v1_endpoint}/secured-ping"

    @property
    def buckets_url(self) -> str:
        return f"{self.api_v1_endpoint}/buckets"

    def bucket_url(self, name: str) -> str:
        return f"{self.api_v1_endpoint}/buckets/{name}"


@pytest.fixture
async def buckets_api(config: Config) -> AsyncIterator[BucketsApiEndpoints]:
    app = await create_app(config)
    async with create_local_app_server(app, port=8080) as address:
        yield BucketsApiEndpoints(address=address)


@pytest.fixture
async def grant_bucket_permission(
    auth_client: AuthClient,
    token_factory: Callable[[str], str],
    admin_token: str,
    cluster_name: str,
) -> AsyncIterator[Callable[[_User, str, str], Awaitable[None]]]:
    async def _grant(user: _User, owner: str, id: str, action: str = "read") -> None:
        permission = Permission(
            uri=f"blob://{cluster_name}/{owner}/{id}", action=action
        )
        await auth_client.grant_user_permissions(user.name, [permission], admin_token)

    yield _grant


class TestApi:
    async def test_ping(
        self, buckets_api: BucketsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.get(buckets_api.ping_url) as resp:
            assert resp.status == HTTPOk.status_code
            text = await resp.text()
            assert text == "Pong"

    async def test_secured_ping(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        admin_token: str,
    ) -> None:
        headers = {"Authorization": f"Bearer {admin_token}"}
        async with client.get(buckets_api.secured_ping_url, headers=headers) as resp:
            assert resp.status == HTTPOk.status_code
            text = await resp.text()
            assert text == "Secured Pong"

    async def test_secured_ping_no_token_provided_unauthorized(
        self, buckets_api: BucketsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        url = buckets_api.secured_ping_url
        async with client.get(url) as resp:
            assert resp.status == HTTPUnauthorized.status_code

    async def test_secured_ping_non_existing_token_unauthorized(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        token_factory: Callable[[str], str],
    ) -> None:
        url = buckets_api.secured_ping_url
        token = token_factory("non-existing-user")
        headers = {"Authorization": f"Bearer {token}"}
        async with client.get(url, headers=headers) as resp:
            assert resp.status == HTTPUnauthorized.status_code

    async def test_ping_unknown_origin(
        self, buckets_api: BucketsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.get(
            buckets_api.ping_url, headers={"Origin": "http://unknown"}
        ) as response:
            assert response.status == HTTPOk.status_code, await response.text()
            assert "Access-Control-Allow-Origin" not in response.headers

    async def test_ping_allowed_origin(
        self, buckets_api: BucketsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.get(
            buckets_api.ping_url, headers={"Origin": "https://neu.ro"}
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            assert resp.headers["Access-Control-Allow-Origin"] == "https://neu.ro"
            assert resp.headers["Access-Control-Allow-Credentials"] == "true"

    async def test_ping_options_no_headers(
        self, buckets_api: BucketsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.options(buckets_api.ping_url) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()
            assert await resp.text() == (
                "CORS preflight request failed: "
                "origin header is not specified in the request"
            )

    async def test_ping_options_unknown_origin(
        self, buckets_api: BucketsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.options(
            buckets_api.ping_url,
            headers={
                "Origin": "http://unknown",
                "Access-Control-Request-Method": "GET",
            },
        ) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()
            assert await resp.text() == (
                "CORS preflight request failed: "
                "origin 'http://unknown' is not allowed"
            )

    async def test_ping_options(
        self, buckets_api: BucketsApiEndpoints, client: aiohttp.ClientSession
    ) -> None:
        async with client.options(
            buckets_api.ping_url,
            headers={
                "Origin": "https://neu.ro",
                "Access-Control-Request-Method": "GET",
            },
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            assert resp.headers["Access-Control-Allow-Origin"] == "https://neu.ro"
            assert resp.headers["Access-Control-Allow-Credentials"] == "true"
            assert resp.headers["Access-Control-Allow-Methods"] == "GET"

    BucketFactory = Callable[[Optional[str], _User], Awaitable[Dict[str, Any]]]

    @pytest.fixture()
    async def make_bucket(
        self, buckets_api: BucketsApiEndpoints, client: aiohttp.ClientSession
    ) -> BucketFactory:
        async def _factory(name: Optional[str], user: _User) -> Dict[str, Any]:
            async with client.post(
                buckets_api.buckets_url,
                headers=user.headers,
                json={
                    "name": name,
                },
            ) as resp:
                assert resp.status == HTTPCreated.status_code, await resp.text()
                return await resp.json()

        return _factory

    async def test_create_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        before = utc_now()
        payload = await make_bucket("test_bucket", regular_user)
        after = utc_now()
        assert "id" in payload
        assert payload["name"] == "test_bucket"
        assert "test_bucket" in payload["credentials"]["bucket_name"]
        assert payload["provider"] == "aws"
        assert payload["owner"] == regular_user.name
        assert before <= datetime.fromisoformat(payload["created_at"]) <= after

    async def test_create_bucket_duplicate(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        await make_bucket("test_bucket", regular_user)
        async with client.post(
            buckets_api.buckets_url,
            headers=regular_user.headers,
            json={
                "name": "test_bucket",
            },
        ) as resp:
            assert resp.status == HTTPConflict.status_code, await resp.text()
            payload = await resp.json()
            assert payload["code"] == "unique"

    async def test_get_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        create_resp = await make_bucket("test_bucket", regular_user)
        async with client.get(
            buckets_api.bucket_url(create_resp["id"]),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == create_resp

    async def test_get_bucket_by_name(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        create_resp = await make_bucket("test_bucket", regular_user)
        async with client.get(
            buckets_api.bucket_url("test_bucket"),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == create_resp

    async def test_get_bucket_not_found(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        async with client.get(
            buckets_api.bucket_url("test_bucket"),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPNotFound.status_code, await resp.text()

    async def test_list_buckets(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        buckets_data = []
        for index in range(5):
            bucket_data = await make_bucket(f"test_bucket_{index}", regular_user)
            buckets_data.append(bucket_data)
        for index in range(5):
            bucket_data = await make_bucket(None, regular_user)
            buckets_data.append(bucket_data)
        async with client.get(
            buckets_api.buckets_url,
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert len(payload) == len(buckets_data)
            for bucket_data in buckets_data:
                assert bucket_data in payload

    async def test_list_buckets_ndjson(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:

        headers = {"Accept": "application/x-ndjson"}
        async with client.get(
            buckets_api.buckets_url,
            headers={**regular_user.headers, **headers},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = []
            async for line in resp.content:
                payload.append(json.loads(line))
            assert payload == []

        buckets_data = []
        for index in range(5):
            bucket_data = await make_bucket(f"test_bucket_{index}", regular_user)
            buckets_data.append(bucket_data)

        async with client.get(
            buckets_api.buckets_url,
            headers={**regular_user.headers, **headers},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = []
            async for line in resp.content:
                payload.append(json.loads(line))
            assert len(payload) == len(buckets_data)
            for bucket_data in buckets_data:
                assert bucket_data in payload

    async def test_delete_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        data = await make_bucket("test_bucket", regular_user)
        async with client.delete(
            buckets_api.bucket_url(data["id"]),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPNoContent.status_code, await resp.text()
        async with client.get(
            buckets_api.buckets_url,
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == []

    async def test_delete_bucket_by_name(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        await make_bucket("test_bucket", regular_user)
        async with client.delete(
            buckets_api.bucket_url("test_bucket"),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPNoContent.status_code, await resp.text()
        async with client.get(
            buckets_api.buckets_url,
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == []

    async def test_delete_bucket_not_existing(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        async with client.delete(
            buckets_api.bucket_url("test_bucket"),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPNotFound.status_code, await resp.text()

    async def test_cant_get_another_user_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        make_bucket: BucketFactory,
    ) -> None:
        create_resp = await make_bucket("test_bucket", regular_user)
        async with client.get(
            buckets_api.bucket_url(create_resp["id"]),
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()

    async def test_cant_list_another_user_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        make_bucket: BucketFactory,
    ) -> None:
        await make_bucket("test_bucket", regular_user)
        async with client.get(
            buckets_api.buckets_url,
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            assert await resp.json() == []

    async def test_cant_delete_another_user_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        make_bucket: BucketFactory,
    ) -> None:
        create_resp = await make_bucket("test_bucket", regular_user)
        async with client.delete(
            buckets_api.bucket_url(create_resp["id"]),
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()

    async def test_can_get_shared_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        grant_bucket_permission: Callable[[_User, str, str], Awaitable[None]],
        make_bucket: BucketFactory,
    ) -> None:
        create_resp1 = await make_bucket("test_bucket1", regular_user)
        create_resp2 = await make_bucket("test_bucket2", regular_user)
        await grant_bucket_permission(
            regular_user2, regular_user.name, create_resp1["id"]
        )
        await grant_bucket_permission(
            regular_user2, regular_user.name, create_resp2["name"]
        )
        async with client.get(
            buckets_api.bucket_url(create_resp1["id"]),
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()

        async with client.get(
            buckets_api.bucket_url(create_resp2["id"]),
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()

        async with client.get(
            buckets_api.buckets_url,
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            assert len(await resp.json()) == 2

    async def test_can_delete_only_shared_for_write_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        grant_bucket_permission: Callable[[_User, str, str, str], Awaitable[None]],
        make_bucket: BucketFactory,
    ) -> None:
        create_resp1 = await make_bucket("test_bucket1", regular_user)
        create_resp2 = await make_bucket("test_bucket2", regular_user)
        await grant_bucket_permission(
            regular_user2, regular_user.name, create_resp1["id"], "read"
        )
        await grant_bucket_permission(
            regular_user2, regular_user.name, create_resp2["id"], "write"
        )
        async with client.delete(
            buckets_api.bucket_url(create_resp1["id"]),
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()
        async with client.delete(
            buckets_api.bucket_url(create_resp2["id"]),
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPNoContent.status_code, await resp.text()
