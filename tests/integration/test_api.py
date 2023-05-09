import json
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional, Protocol

import aiohttp
import pytest
from aiohttp.web import HTTPOk
from aiohttp.web_exceptions import (
    HTTPBadRequest,
    HTTPConflict,
    HTTPCreated,
    HTTPForbidden,
    HTTPNoContent,
    HTTPNotFound,
    HTTPUnauthorized,
    HTTPUnprocessableEntity,
)
from neuro_auth_client import AuthClient, Permission
from yarl import URL

from platform_buckets_api.api import create_app
from platform_buckets_api.config import Config
from platform_buckets_api.utils import utc_now

from .auth import UserFactory, _User
from .conftest import ApiAddress, create_local_app_server


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
        return f"{self.api_v1_endpoint}/buckets/buckets"

    @property
    def bucket_import_url(self) -> str:
        return f"{self.api_v1_endpoint}/buckets/buckets/import/external"

    @property
    def bucket_by_path(self) -> str:
        return f"{self.api_v1_endpoint}/buckets/buckets/find/by_path"

    def bucket_url(self, name: str) -> str:
        return f"{self.buckets_url}/{name}"

    def bucket_make_tmp_credentials_url(self, name: str) -> str:
        return f"{self.bucket_url(name)}/make_tmp_credentials"

    def bucket_sign_blob_url(self, name: str) -> str:
        return f"{self.bucket_url(name)}/sign_blob_url"

    @property
    def credentials_url(self) -> str:
        return f"{self.api_v1_endpoint}/buckets/persistent_credentials"

    def credential_url(self, name: str) -> str:
        return f"{self.credentials_url}/{name}"


@pytest.fixture
async def buckets_api(config: Config) -> AsyncIterator[BucketsApiEndpoints]:
    app = await create_app(config)
    async with create_local_app_server(app, port=8080) as address:
        yield BucketsApiEndpoints(address=address)


@pytest.fixture
async def buckets_api_creation_disabled(
    config_creation_disabled: Config,
) -> AsyncIterator[BucketsApiEndpoints]:
    app = await create_app(config_creation_disabled)
    async with create_local_app_server(app, port=8080) as address:
        yield BucketsApiEndpoints(address=address)


@pytest.fixture
async def grant_project_permission(
    auth_client: AuthClient,
    token_factory: Callable[[str], str],
    admin_token: str,
    cluster_name: str,
) -> AsyncIterator[Callable[[_User, str, str], Awaitable[None]]]:
    async def _grant(user: _User, project_name: str, action: str = "read") -> None:
        permission = Permission(
            uri=f"blob://{cluster_name}/{project_name}", action=action
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

    class BucketFactory(Protocol):
        async def __call__(
            self,
            name: Optional[str],
            user: _User,
            project_name: str = "test-project",
            org_name: Optional[str] = None,
        ) -> dict[str, Any]:
            pass

    @pytest.fixture()
    async def make_bucket(
        self, buckets_api: BucketsApiEndpoints, client: aiohttp.ClientSession
    ) -> BucketFactory:
        async def _factory(
            name: Optional[str],
            user: _User,
            project_name: str = "test-project",
            org_name: Optional[str] = None,
        ) -> dict[str, Any]:
            payload = {
                "name": name,
                "project_name": project_name,
            }
            if org_name:
                payload["org_name"] = org_name
            async with client.post(
                buckets_api.buckets_url,
                headers=user.headers,
                json=payload,
            ) as resp:
                assert resp.status == HTTPCreated.status_code, await resp.text()
                return await resp.json()

        return _factory

    @pytest.fixture()
    async def import_bucket(
        self, buckets_api: BucketsApiEndpoints, client: aiohttp.ClientSession
    ) -> BucketFactory:
        async def _factory(
            name: Optional[str],
            user: _User,
            project_name: str = "test-project",
            org_name: Optional[str] = None,
        ) -> dict[str, Any]:
            payload = {
                "name": name,
                "project_name": project_name,
                "provider_bucket_name": f"in-provider-{name}",
                "provider": "aws",
                "credentials": {"key": f"key-for-{name}"},
            }
            if org_name:
                payload["org_name"] = org_name
            async with client.post(
                buckets_api.bucket_import_url,
                headers=user.headers,
                json=payload,
            ) as resp:
                assert resp.status == HTTPCreated.status_code, await resp.text()
                return await resp.json()

        return _factory

    CredentialsFactory = Callable[
        [Optional[str], _User, list[str]], Awaitable[dict[str, Any]]
    ]
    CredentialsFactoryWithReadOnly = Callable[
        [Optional[str], _User, list[str], bool], Awaitable[dict[str, Any]]
    ]

    @pytest.fixture()
    async def make_credentials(
        self, buckets_api: BucketsApiEndpoints, client: aiohttp.ClientSession
    ) -> CredentialsFactory:
        async def _factory(
            name: Optional[str],
            user: _User,
            bucket_ids: list[str],
            read_only: bool = False,
        ) -> dict[str, Any]:
            async with client.post(
                buckets_api.credentials_url,
                headers=user.headers,
                json={
                    "name": name,
                    "bucket_ids": bucket_ids,
                    "read_only": read_only,
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
        payload = await make_bucket("test-bucket", regular_user)
        after = utc_now()
        assert "id" in payload
        assert payload["name"] == "test-bucket"
        assert payload["provider"] in ("aws", "minio")
        assert payload["owner"] == regular_user.name
        assert payload["project_name"] == "test-project"
        assert not payload["imported"]
        assert before <= datetime.fromisoformat(payload["created_at"]) <= after

    async def test_create_bucket_same_name_different_project(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        make_bucket: BucketFactory,
        regular_user_factory: UserFactory,
    ) -> None:
        regular_user1 = await regular_user_factory(project_name="test-project1")
        bucket1 = await make_bucket(
            "test-bucket", regular_user1, project_name="test-project1"
        )
        assert bucket1["name"] == "test-bucket"
        assert bucket1["owner"] == regular_user1.name
        assert bucket1["project_name"] == "test-project1"

        regular_user2 = await regular_user_factory(project_name="test-project2")
        bucket2 = await make_bucket(
            "test-bucket", regular_user2, project_name="test-project2"
        )
        assert bucket2["id"] != bucket1["id"]
        assert bucket2["name"] == "test-bucket"
        assert bucket2["owner"] == regular_user2.name
        assert bucket2["project_name"] == "test-project2"

    async def test_create_bucket_with_org(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: UserFactory,
        make_bucket: BucketFactory,
    ) -> None:
        regular_user = await regular_user_factory(org_name="test-org")
        before = utc_now()
        payload = await make_bucket("test-bucket", regular_user, org_name="test-org")
        after = utc_now()
        assert "id" in payload
        assert payload["name"] == "test-bucket"
        assert payload["provider"] in ("aws", "minio")
        assert payload["owner"] == regular_user.name
        assert payload["org_name"] == "test-org"
        assert not payload["imported"]
        assert before <= datetime.fromisoformat(payload["created_at"]) <= after

    async def test_create_bucket_when_disabled(
        self,
        buckets_api_creation_disabled: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
    ) -> None:
        async with client.post(
            buckets_api_creation_disabled.buckets_url,
            headers=regular_user.headers,
            json={
                "name": "anything",
            },
        ) as resp:
            assert resp.status == HTTPUnprocessableEntity.status_code, await resp.text()
            error = await resp.json()
            assert error["code"] == "disabled"

    async def test_import_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        import_bucket: BucketFactory,
    ) -> None:
        before = utc_now()
        payload = await import_bucket("test-bucket", regular_user)
        after = utc_now()
        assert "id" in payload
        assert payload["name"] == "test-bucket"
        assert payload["provider"] == "aws"
        assert payload["owner"] == regular_user.name
        assert payload["imported"]
        assert before <= datetime.fromisoformat(payload["created_at"]) <= after

    async def test_import_bucket_with_org(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: UserFactory,
        import_bucket: BucketFactory,
    ) -> None:
        regular_user = await regular_user_factory(org_name="test-org")
        before = utc_now()
        payload = await import_bucket("test-bucket", regular_user, org_name="test-org")
        after = utc_now()
        assert "id" in payload
        assert payload["name"] == "test-bucket"
        assert payload["provider"] == "aws"
        assert payload["owner"] == regular_user.name
        assert payload["org_name"] == "test-org"
        assert payload["imported"]
        assert before <= datetime.fromisoformat(payload["created_at"]) <= after

    async def test_make_bucket_tmp_credentials(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        create_resp = await make_bucket("test-bucket", regular_user)
        async with client.post(
            buckets_api.bucket_make_tmp_credentials_url(create_resp["id"]),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload["bucket_id"] == create_resp["id"]
            assert payload["provider"] == create_resp["provider"]
            assert not payload["read_only"]
            assert "test-bucket" in payload["credentials"]["bucket_name"]

    async def test_make_bucket_tmp_credentials_readonly(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        grant_project_permission: Callable[[_User, str], Awaitable[None]],
        make_bucket: BucketFactory,
    ) -> None:
        create_resp = await make_bucket(
            "test-bucket", regular_user, project_name=regular_user.name
        )
        await grant_project_permission(regular_user2, create_resp["project_name"])
        async with client.post(
            buckets_api.bucket_make_tmp_credentials_url(create_resp["id"]),
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload["bucket_id"] == create_resp["id"]
            assert payload["provider"] == create_resp["provider"]
            assert payload["read_only"]
            assert "test-bucket" in payload["credentials"]["bucket_name"]

    async def test_imported_bucket_tmp_credentials(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        import_bucket: BucketFactory,
    ) -> None:
        create_resp = await import_bucket("test-bucket", regular_user)
        async with client.post(
            buckets_api.bucket_make_tmp_credentials_url(create_resp["id"]),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload["bucket_id"] == create_resp["id"]
            assert payload["provider"] == create_resp["provider"]
            assert not payload["read_only"]
            assert payload["credentials"]["bucket_name"] == "in-provider-test-bucket"
            assert payload["credentials"]["key"] == "key-for-test-bucket"

    async def test_imported_bucket_tmp_credentials_readonly(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        grant_project_permission: Callable[[_User, str], Awaitable[None]],
        import_bucket: BucketFactory,
    ) -> None:
        create_resp = await import_bucket("test-bucket", regular_user)
        await grant_project_permission(regular_user2, create_resp["project_name"])
        async with client.post(
            buckets_api.bucket_make_tmp_credentials_url(create_resp["id"]),
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload["bucket_id"] == create_resp["id"]
            assert payload["provider"] == create_resp["provider"]
            assert payload["read_only"]
            assert payload["credentials"]["bucket_name"] == "in-provider-test-bucket"
            assert payload["credentials"]["key"] == "key-for-test-bucket"

    async def test_make_signed_url(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        create_resp = await make_bucket("test-bucket", regular_user)
        async with client.post(
            buckets_api.bucket_sign_blob_url(create_resp["id"]),
            headers=regular_user.headers,
            json={"key": "some/file"},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert URL(payload["url"])

    async def test_make_bucket_public_non_public(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        create_resp = await make_bucket("test-bucket", regular_user)
        async with client.patch(
            buckets_api.bucket_url(create_resp["id"]),
            headers=regular_user.headers,
            json={"public": True},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload["public"]
        async with client.patch(
            buckets_api.bucket_url(create_resp["id"]),
            headers=regular_user.headers,
            json={"public": False},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert not payload["public"]

    async def test_create_bucket_duplicate(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        bucket = await make_bucket("test-bucket", regular_user)
        async with client.post(
            buckets_api.buckets_url,
            headers=regular_user.headers,
            json={
                "name": "test-bucket",
                "project_name": bucket["project_name"],
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
        create_resp = await make_bucket("test-bucket", regular_user)
        async with client.get(
            buckets_api.bucket_url(create_resp["id"]),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == create_resp

    async def test_get_bucket_with_org(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: UserFactory,
        make_bucket: BucketFactory,
    ) -> None:
        regular_user = await regular_user_factory(org_name="test-org")
        create_resp = await make_bucket(
            "test-bucket", regular_user, org_name="test-org"
        )
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
        create_resp = await make_bucket("test-bucket", regular_user)
        async with client.get(
            buckets_api.bucket_url("test-bucket"),
            headers=regular_user.headers,
            params={"project_name": "test-project"},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == create_resp

    async def test_get_bucket_by_name__for_legacy_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        create_resp = await make_bucket(
            "test-bucket", regular_user, project_name=regular_user.name
        )
        async with client.get(
            buckets_api.bucket_url("test-bucket"), headers=regular_user.headers
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == create_resp

    async def test_get_bucket_by_name__bad_request(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
    ) -> None:
        async with client.get(
            buckets_api.bucket_url("test-bucket"),
            headers=regular_user.headers,
            params={"owner": regular_user.name, "project_name": "test-project"},
        ) as resp:
            assert resp.status == HTTPBadRequest.status_code, await resp.text()
        async with client.get(
            buckets_api.bucket_url("test-bucket"),
            headers=regular_user.headers,
            params={"owner": regular_user.name, "org_name": "test-org"},
        ) as resp:
            assert resp.status == HTTPBadRequest.status_code, await resp.text()
        async with client.get(
            buckets_api.bucket_url("test-bucket"),
            headers=regular_user.headers,
            params={"org_name": "test-org"},
        ) as resp:
            assert resp.status == HTTPBadRequest.status_code, await resp.text()

    async def test_get_bucket_by_path(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: UserFactory,
        make_bucket: BucketFactory,
    ) -> None:
        regular_user = await regular_user_factory(org_name="test-org")
        create_resp = await make_bucket(
            "test-bucket", regular_user, org_name="test-org"
        )
        project_name = create_resp["project_name"]
        async with client.get(
            buckets_api.bucket_by_path,
            params={"path": f"test-org/{project_name}/test-bucket"},
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
            buckets_api.bucket_url("test-bucket"),
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
            bucket_data = await make_bucket(f"test-bucket-{index}", regular_user)
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

    async def test_list_buckets_org_level(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: UserFactory,
        make_bucket: BucketFactory,
    ) -> None:
        user1 = await regular_user_factory(org_name="test-org")
        user2 = await regular_user_factory(org_name="test-org")
        user3 = await regular_user_factory(org_name="test-org", org_level=True)
        bucket1 = await make_bucket("bucket-1", user1, org_name="test-org")
        bucket2 = await make_bucket("bucket-2", user2, org_name="test-org")
        buckets_data = [bucket1, bucket2]
        async with client.get(
            buckets_api.buckets_url,
            headers=user3.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert len(payload) == len(buckets_data)
            for bucket_data in buckets_data:
                assert bucket_data in payload

    async def test_list_buckets_no_org(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: UserFactory,
        make_bucket: BucketFactory,
    ) -> None:
        user = await regular_user_factory()
        bucket = await make_bucket("bucket-1", user)
        async with client.get(buckets_api.buckets_url, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == [bucket]
        async with client.get(
            buckets_api.buckets_url,
            headers=user.headers,
            params={"org_name": "NO_ORG"},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == [bucket]
        async with client.get(
            buckets_api.buckets_url,
            headers=user.headers,
            params={"org_name": "test-org"},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == []

    async def test_list_buckets_in_org(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: UserFactory,
        make_bucket: BucketFactory,
    ) -> None:
        user = await regular_user_factory(org_name="test-org")
        bucket = await make_bucket("bucket-1", user, org_name="test-org")
        async with client.get(buckets_api.buckets_url, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == [bucket]
        async with client.get(
            buckets_api.buckets_url,
            headers=user.headers,
            params={"org_name": "test-org"},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == [bucket]
        async with client.get(
            buckets_api.buckets_url,
            headers=user.headers,
            params={"org_name": "other-test-org"},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == []

    async def test_list_buckets_in_project(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: UserFactory,
        make_bucket: BucketFactory,
    ) -> None:
        user = await regular_user_factory()
        bucket = await make_bucket("bucket-1", user)
        async with client.get(buckets_api.buckets_url, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == [bucket]
        async with client.get(
            buckets_api.buckets_url,
            headers=user.headers,
            params={"project_name": "test-project"},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == [bucket]
        async with client.get(
            buckets_api.buckets_url,
            headers=user.headers,
            params={"project_name": "other-test-project"},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == []

    async def test_list_buckets_in_legacy_project(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user_factory: UserFactory,
        make_bucket: BucketFactory,
    ) -> None:
        user = await regular_user_factory()
        bucket = await make_bucket("bucket-1", user, project_name=user.name)
        async with client.get(buckets_api.buckets_url, headers=user.headers) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == [bucket]
        async with client.get(
            buckets_api.buckets_url,
            headers=user.headers,
            params={"project_name": user.name},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == [bucket]
        async with client.get(
            buckets_api.buckets_url,
            headers=user.headers,
            params={"project_name": "test-project"},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == []

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
            bucket_data = await make_bucket(f"test-bucket-{index}", regular_user)
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
        data = await make_bucket("test-bucket", regular_user)
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

    async def test_delete_bucket_with_credentials(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
        make_credentials: CredentialsFactory,
    ) -> None:
        bucket1 = await make_bucket("test-bucket1", regular_user)
        bucket2 = await make_bucket("test-bucket2", regular_user)

        creds1 = await make_credentials(
            "test-creds1", regular_user, [bucket1["id"], bucket2["id"]]
        )
        creds2 = await make_credentials("test-creds2", regular_user, [bucket1["id"]])
        creds3 = await make_credentials("test-creds3", regular_user, [bucket2["id"]])
        async with client.delete(
            buckets_api.bucket_url(bucket1["id"]),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPNoContent.status_code, await resp.text()

        # Creds to multiple buckets - bucket removed from list
        async with client.get(
            buckets_api.credential_url(creds1["id"]),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert len(payload["credentials"]) == 1
            assert payload["credentials"][0]["bucket_id"] == bucket2["id"]

        # Creds to single buckets - creds removed
        async with client.get(
            buckets_api.credential_url(creds2["id"]),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPNotFound.status_code, await resp.text()

        # Creds to different buckets - nothing changed
        async with client.get(
            buckets_api.credential_url(creds3["id"]),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == creds3

    async def test_delete_bucket_by_name(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
    ) -> None:
        await make_bucket("test-bucket", regular_user)
        async with client.delete(
            buckets_api.bucket_url("test-bucket"),
            headers=regular_user.headers,
            params={"project_name": "test-project"},
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
    ) -> None:
        async with client.delete(
            buckets_api.bucket_url("test-bucket"),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPNotFound.status_code, await resp.text()

    async def test_cannot_get_another_user_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        make_bucket: BucketFactory,
    ) -> None:
        create_resp = await make_bucket(
            "test-bucket", regular_user, project_name=regular_user.name
        )
        async with client.get(
            buckets_api.bucket_url(create_resp["id"]),
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()

    async def test_cannot_list_another_user_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        make_bucket: BucketFactory,
    ) -> None:
        await make_bucket("test-bucket", regular_user, project_name=regular_user.name)
        async with client.get(
            buckets_api.buckets_url,
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            assert await resp.json() == []

    async def test_cannot_delete_another_user_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        make_bucket: BucketFactory,
    ) -> None:
        create_resp = await make_bucket(
            "test-bucket", regular_user, project_name=regular_user.name
        )
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
        grant_project_permission: Callable[[_User, str], Awaitable[None]],
        make_bucket: BucketFactory,
    ) -> None:
        create_resp = await make_bucket("test-bucket1", regular_user)
        await grant_project_permission(regular_user2, create_resp["project_name"])
        async with client.get(
            buckets_api.bucket_url(create_resp["id"]),
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()

        async with client.get(
            buckets_api.buckets_url,
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            assert len(await resp.json()) == 1

    async def test_can_get_shared_bucket_by_name(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        grant_project_permission: Callable[[_User, str], Awaitable[None]],
        make_bucket: BucketFactory,
    ) -> None:
        create_resp1 = await make_bucket("test-bucket1", regular_user)
        await grant_project_permission(regular_user2, create_resp1["project_name"])
        async with client.get(
            buckets_api.bucket_url(create_resp1["name"]),
            params={"project_name": create_resp1["project_name"]},
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()

    async def test_can_delete_only_shared_for_write_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        grant_project_permission: Callable[[_User, str, str], Awaitable[None]],
        make_bucket: BucketFactory,
    ) -> None:
        create_resp1 = await make_bucket("test-bucket1", regular_user)
        create_resp2 = await make_bucket("test-bucket2", regular_user)
        await grant_project_permission(
            regular_user2, create_resp2["project_name"], "read"
        )
        async with client.delete(
            buckets_api.bucket_url(create_resp1["id"]),
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPForbidden.status_code, await resp.text()
        await grant_project_permission(
            regular_user2, create_resp2["project_name"], "write"
        )
        async with client.delete(
            buckets_api.bucket_url(create_resp2["id"]),
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPNoContent.status_code, await resp.text()

    async def test_create_credentials(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
        make_credentials: CredentialsFactory,
    ) -> None:
        bucket1 = await make_bucket("test-bucket1", regular_user)
        bucket2 = await make_bucket("test-bucket2", regular_user)
        payload = await make_credentials(
            "test-creds", regular_user, [bucket1["id"], bucket2["id"]]
        )
        assert payload["id"]
        assert payload["name"] == "test-creds"
        assert payload["owner"] == regular_user.name
        assert not payload["read_only"]
        assert len(payload["credentials"]) == 2
        bucket1_creds, bucket2_creds = payload["credentials"]
        if bucket1_creds["bucket_id"] == bucket2["id"]:
            bucket1_creds, bucket2_creds = bucket2_creds, bucket1_creds
        assert bucket1_creds["bucket_id"] == bucket1["id"]
        assert bucket1_creds["provider"] == bucket1["provider"]
        assert "test-bucket1" in bucket1_creds["credentials"]["bucket_name"]

        assert bucket2_creds["bucket_id"] == bucket2["id"]
        assert bucket2_creds["provider"] == bucket2["provider"]
        assert "test-bucket2" in bucket2_creds["credentials"]["bucket_name"]

    async def test_create_credentials_when_disabled(
        self,
        buckets_api_creation_disabled: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
    ) -> None:
        async with client.post(
            buckets_api_creation_disabled.credentials_url,
            headers=regular_user.headers,
            json={
                "name": "any",
                "bucket_ids": ["1", "2", "3"],
                "read_only": False,
            },
        ) as resp:
            assert resp.status == HTTPUnprocessableEntity.status_code, await resp.text()
            error = await resp.json()
            assert error["code"] == "disabled"

    async def test_create_credentials_read_only(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
        make_credentials: CredentialsFactoryWithReadOnly,
    ) -> None:
        bucket1 = await make_bucket("test-bucket1", regular_user)
        bucket2 = await make_bucket("test-bucket2", regular_user)
        payload = await make_credentials(
            "test-creds", regular_user, [bucket1["id"], bucket2["id"]], True
        )
        assert payload["id"]
        assert payload["name"] == "test-creds"
        assert payload["owner"] == regular_user.name
        assert payload["read_only"]
        assert len(payload["credentials"]) == 2
        bucket1_creds, bucket2_creds = payload["credentials"]
        if bucket1_creds["bucket_id"] == bucket2["id"]:
            bucket1_creds, bucket2_creds = bucket2_creds, bucket1_creds
        assert bucket1_creds["bucket_id"] == bucket1["id"]
        assert bucket1_creds["provider"] == bucket1["provider"]
        assert "test-bucket1" in bucket1_creds["credentials"]["bucket_name"]

        assert bucket2_creds["bucket_id"] == bucket2["id"]
        assert bucket2_creds["provider"] == bucket2["provider"]
        assert "test-bucket2" in bucket2_creds["credentials"]["bucket_name"]

    async def test_cannot_create_credential_for_imported_bucket(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        import_bucket: BucketFactory,
        make_credentials: CredentialsFactory,
    ) -> None:
        bucket = await import_bucket("test-bucket", regular_user)
        async with client.post(
            buckets_api.credentials_url,
            headers=regular_user.headers,
            json={
                "name": "test-creds",
                "bucket_ids": [bucket["id"]],
            },
        ) as resp:
            assert resp.status == HTTPBadRequest.status_code

    async def test_get_credentials(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
        make_credentials: CredentialsFactory,
    ) -> None:
        bucket1 = await make_bucket("test-bucket1", regular_user)
        bucket2 = await make_bucket("test-bucket2", regular_user)
        create_resp = await make_credentials(
            "test-creds", regular_user, [bucket1["id"], bucket2["id"]]
        )
        async with client.get(
            buckets_api.credential_url(create_resp["id"]),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == create_resp

    async def test_get_credentials_by_name(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
        make_credentials: CredentialsFactory,
    ) -> None:
        bucket1 = await make_bucket("test-bucket1", regular_user)
        bucket2 = await make_bucket("test-bucket2", regular_user)
        create_resp = await make_credentials(
            "test_credentials", regular_user, [bucket1["id"], bucket2["id"]]
        )
        async with client.get(
            buckets_api.credential_url("test_credentials"),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == create_resp

    async def test_get_credentials_not_found(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
    ) -> None:
        async with client.get(
            buckets_api.credential_url("test_credentials"),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPNotFound.status_code, await resp.text()

    async def test_list_credentials(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
        make_credentials: CredentialsFactory,
    ) -> None:
        bucket1 = await make_bucket("test-bucket1", regular_user)
        bucket2 = await make_bucket("test-bucket2", regular_user)
        credentials_list = []
        for index in range(5):
            credentials_data = await make_credentials(
                f"test-creds-{index}", regular_user, [bucket1["id"], bucket2["id"]]
            )
            credentials_list.append(credentials_data)
        for index in range(5):
            credentials_data = await make_credentials(
                None, regular_user, [bucket1["id"], bucket2["id"]]
            )
            credentials_list.append(credentials_data)
        async with client.get(
            buckets_api.credentials_url,
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert len(payload) == len(credentials_list)
            for credentials_data in credentials_list:
                assert credentials_data in payload

    async def test_list_credentials_ndjson(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
        make_credentials: CredentialsFactory,
    ) -> None:
        headers = {"Accept": "application/x-ndjson"}
        async with client.get(
            buckets_api.credentials_url,
            headers={**regular_user.headers, **headers},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = []
            async for line in resp.content:
                payload.append(json.loads(line))
            assert payload == []

        bucket1 = await make_bucket("test-bucket1", regular_user)
        bucket2 = await make_bucket("test-bucket2", regular_user)
        credentials_list = []
        for index in range(5):
            credentials_data = await make_credentials(
                f"test-creds-{index}", regular_user, [bucket1["id"], bucket2["id"]]
            )
            credentials_list.append(credentials_data)
        for index in range(5):
            credentials_data = await make_credentials(
                None, regular_user, [bucket1["id"], bucket2["id"]]
            )
            credentials_list.append(credentials_data)

        async with client.get(
            buckets_api.credentials_url,
            headers={**regular_user.headers, **headers},
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = []
            async for line in resp.content:
                payload.append(json.loads(line))
            assert len(payload) == len(credentials_list)
            for credentials_data in credentials_list:
                assert credentials_data in payload

    async def test_delete_credentials(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
        make_credentials: CredentialsFactory,
    ) -> None:
        bucket1 = await make_bucket("test-bucket1", regular_user)
        bucket2 = await make_bucket("test-bucket2", regular_user)
        data = await make_credentials(
            "test_credentials", regular_user, [bucket1["id"], bucket2["id"]]
        )
        async with client.delete(
            buckets_api.credential_url(data["id"]),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPNoContent.status_code, await resp.text()
        async with client.get(
            buckets_api.credentials_url,
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == []

    async def test_delete_credentials_by_name(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_bucket: BucketFactory,
        make_credentials: CredentialsFactory,
    ) -> None:
        bucket1 = await make_bucket("test-bucket1", regular_user)
        bucket2 = await make_bucket("test-bucket2", regular_user)
        await make_credentials(
            "test_credentials", regular_user, [bucket1["id"], bucket2["id"]]
        )
        async with client.delete(
            buckets_api.credential_url("test_credentials"),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPNoContent.status_code, await resp.text()
        async with client.get(
            buckets_api.credentials_url,
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            payload = await resp.json()
            assert payload == []

    async def test_delete_credentials_not_existing(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        make_credentials: BucketFactory,
    ) -> None:
        async with client.delete(
            buckets_api.credential_url("test_credentials"),
            headers=regular_user.headers,
        ) as resp:
            assert resp.status == HTTPNotFound.status_code, await resp.text()

    async def test_cannot_get_another_user_credentials(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        make_bucket: BucketFactory,
        make_credentials: CredentialsFactory,
    ) -> None:
        bucket1 = await make_bucket("test-bucket1", regular_user)
        bucket2 = await make_bucket("test-bucket2", regular_user)
        create_resp = await make_credentials(
            "test_credentials", regular_user, [bucket1["id"], bucket2["id"]]
        )
        async with client.get(
            buckets_api.credential_url(create_resp["id"]),
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPNotFound.status_code, await resp.text()

    async def test_cannot_list_another_user_credentials(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        make_bucket: BucketFactory,
        make_credentials: CredentialsFactory,
    ) -> None:
        bucket1 = await make_bucket("test-bucket1", regular_user)
        bucket2 = await make_bucket("test-bucket2", regular_user)
        await make_credentials(
            "test_credentials", regular_user, [bucket1["id"], bucket2["id"]]
        )
        async with client.get(
            buckets_api.credentials_url,
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPOk.status_code, await resp.text()
            assert await resp.json() == []

    async def test_cannot_delete_another_user_credentials(
        self,
        buckets_api: BucketsApiEndpoints,
        client: aiohttp.ClientSession,
        regular_user: _User,
        regular_user2: _User,
        make_bucket: BucketFactory,
        make_credentials: CredentialsFactory,
    ) -> None:
        bucket1 = await make_bucket("test-bucket1", regular_user)
        bucket2 = await make_bucket("test-bucket2", regular_user)
        create_resp = await make_credentials(
            "test_credentials", regular_user, [bucket1["id"], bucket2["id"]]
        )
        async with client.delete(
            buckets_api.credential_url(create_resp["id"]),
            headers=regular_user2.headers,
        ) as resp:
            assert resp.status == HTTPNotFound.status_code, await resp.text()
