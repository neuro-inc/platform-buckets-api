import asyncio
import base64
import json
import os
import time
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from functools import partial
from typing import Any

import google.cloud.exceptions
import googleapiclient.discovery
import pytest
from google.api_core.exceptions import Forbidden
from google.cloud.iam_credentials_v1 import IAMCredentialsAsyncClient
from google.cloud.storage import Bucket, Client as GCSClient
from google.oauth2.credentials import Credentials
from google.oauth2.service_account import Credentials as SACredentials
from googleapiclient.errors import HttpError
from yarl import URL

from platform_buckets_api.providers import GoogleBucketProvider, run_in_executor
from platform_buckets_api.storage import ProviderBucket

from tests.integration.test_provider_base import (
    BUCKET_NAME_PREFIX,
    ROLE_NAME_PREFIX,
    BasicBucketClient,
    ProviderTestOption,
    TestProviderBase,
    _make_bucket_name,
    as_admin_cm,
)

BUCKET_SA_PREFIX = "bucket-e2e-test-"




@run_in_executor
def gcs_bucket_exists(gs_client: GCSClient, name: str) -> bool:
    try:
        return gs_client.bucket(name).exists()
    except google.cloud.exceptions.NotFound:
        return False


@run_in_executor
def gcs_role_exists(iam: Any, project_id: str, name: str) -> bool:
    try:
        time.sleep(1)  # Wait some time to avoid flakiness
        iam.projects().serviceAccounts().get(
            name=(
                f"projects/{project_id}/serviceAccounts"
                f"/{name}@{project_id}.iam.gserviceaccount.com"
            )
        ).execute()
        return True
    except HttpError as e:
        if e.status_code == 404:
            return False
        raise


class GoogleBasicBucketClient(BasicBucketClient):
    def __init__(self, client: GCSClient, bucket_name: str) -> None:
        self._bucket_name = bucket_name
        self._client = client
        self._bucket_client = client.bucket(bucket_name)

    @classmethod
    @run_in_executor
    def _wait_has_permissions(cls, bucket_client: Bucket) -> None:
        try_cnt = 0
        while True:
            try:
                bucket_client.list_blobs(max_results=1)
                return
            except Forbidden:
                if try_cnt == 30:
                    raise
            try_cnt += 1
            time.sleep(1)

    @classmethod
    @asynccontextmanager
    async def create(
        cls, bucket: ProviderBucket, credentials: Mapping[str, str]
    ) -> AsyncIterator["GoogleBasicBucketClient"]:
        if "access_token" in credentials:
            client = GCSClient(
                project=credentials["project"],
                credentials=Credentials(credentials["access_token"]),
            )
        else:
            credential = credentials["key_data"]
            key_json = json.loads(base64.b64decode(credential).decode())
            client = GCSClient(
                project=credentials["project"],
                credentials=SACredentials.from_service_account_info(info=key_json),
            )
        await cls._wait_has_permissions(client.bucket(bucket.name))
        yield cls(client, bucket.name)
        client.close()

    @run_in_executor
    def read_object(self, key: str) -> bytes:  # type: ignore
        return self._bucket_client.blob(key).download_as_bytes()

    @run_in_executor
    def list_objects(self) -> list[str]:  # type: ignore
        return [entry.name for entry in self._client.list_blobs(self._bucket_name)]

    @run_in_executor
    def delete_object(self, key: str) -> None:  # type: ignore
        self._bucket_client.blob(key).delete()

    @run_in_executor
    def put_object(self, key: str, data: bytes) -> None:  # type: ignore
        self._bucket_client.blob(key).upload_from_string(data)


KEY_JSON_ENV = "GCLOUD_SA_KEY_JSON_B64"


@pytest.fixture()
def gcloud_key_raw() -> str:
    if KEY_JSON_ENV not in os.environ:
        pytest.skip(
            f"Skipping GCS provider tests. Please set {KEY_JSON_ENV}"
            f" environ variables to enable tests"
        )
    return os.environ[KEY_JSON_ENV]


@pytest.fixture()
def gcloud_key_json(gcloud_key_raw: str) -> Mapping[str, str]:
    return json.loads(base64.b64decode(gcloud_key_raw).decode())


@pytest.fixture()
def sa_credentials(gcloud_key_json: Mapping[str, str]) -> SACredentials:
    return SACredentials.from_service_account_info(info=gcloud_key_json)


@pytest.fixture()
def project_id(gcloud_key_json: Mapping[str, str]) -> str:
    return gcloud_key_json["project_id"]


@pytest.fixture()
async def gcs_client(
    sa_credentials: SACredentials, project_id: str
) -> AsyncIterator[GCSClient]:
    @run_in_executor
    def _cleanup_buckets(client: GCSClient) -> None:
        for bucket in client.list_buckets():
            if bucket.name.startswith(BUCKET_NAME_PREFIX):
                client.bucket(bucket.name).delete(force=True)

    client = GCSClient(
        project=project_id,
        credentials=sa_credentials,
    )
    await _cleanup_buckets(client)
    yield client
    await _cleanup_buckets(client)
    client.close()


def _list_all_accounts(iam: Any, project_id: str) -> list[Mapping[str, Any]]:
    accounts = []
    req = iam.projects().serviceAccounts().list(name=f"projects/{project_id}")
    while req:
        resp = req.execute()
        accounts += resp.get("accounts", [])
        req = iam.projects().serviceAccounts().list_next(req, resp)
    return accounts


@pytest.fixture()
async def iam_client(
    sa_credentials: SACredentials, project_id: str
) -> AsyncIterator[Any]:
    @run_in_executor
    def _cleanup_sa(iam: Any) -> None:
        accounts = _list_all_accounts(iam, project_id)
        prefixes = [
            f"projects/{project_id}/serviceAccounts/{ROLE_NAME_PREFIX}",
            f"projects/{project_id}/serviceAccounts/{BUCKET_SA_PREFIX}",
        ]
        for account in accounts:
            if any(account["name"].startswith(prefix) for prefix in prefixes):
                try:
                    iam.projects().serviceAccounts().delete(
                        name=account["name"]
                    ).execute()
                except HttpError:
                    pass  # Probably concurrent remove, just ignore

    iam = googleapiclient.discovery.build("iam", "v1", credentials=sa_credentials)
    await _cleanup_sa(iam)
    yield iam
    await _cleanup_sa(iam)
    iam.close()


@pytest.fixture()
async def iam_client_2(
    sa_credentials: SACredentials,
) -> AsyncIterator[IAMCredentialsAsyncClient]:
    iam_2 = IAMCredentialsAsyncClient(credentials=sa_credentials)
    yield iam_2


@pytest.mark.skip(
    "Disable google test as because they are slow "
    "and unstable when running in parallel"
)
class TestGoogleProvider(TestProviderBase):
    __test__ = True

    @pytest.fixture()
    async def provider_option(
        self,
        gcs_client: GCSClient,
        iam_client: Any,
        iam_client_2: IAMCredentialsAsyncClient,
        project_id: str,
        gcloud_key_raw: str,
    ) -> ProviderTestOption:
        return ProviderTestOption(
            type="gcs",
            provider=GoogleBucketProvider(
                gcs_client=gcs_client,
                iam_client=iam_client,
                iam_client_2=iam_client_2,
                sa_prefix=BUCKET_SA_PREFIX,
            ),
            bucket_exists=partial(gcs_bucket_exists, gcs_client),
            make_client=GoogleBasicBucketClient.create,
            get_admin=as_admin_cm(
                lambda bucket: GoogleBasicBucketClient(gcs_client, bucket.name)
            ),
            role_exists=partial(gcs_role_exists, iam_client, project_id),
            get_public_url=lambda bucket, key: URL(
                f"https://storage.googleapis.com/"
                f"storage/v1/b/{bucket}/o/{key}?alt=media"
            ),
            credentials_for_imported={
                "key_data": gcloud_key_raw,
            },
        )

    async def test_bucket_delete_no_hanging_sa(
        self, provider_option: ProviderTestOption, iam_client: Any, project_id: str
    ) -> None:
        name = _make_bucket_name()
        bucket = await provider_option.provider.create_bucket(name)
        await provider_option.provider.delete_bucket(bucket.name)
        await asyncio.sleep(5)  # Allow GCP to delete accounts
        accounts = await run_in_executor(_list_all_accounts)(iam_client, project_id)
        assert all(bucket.name not in account["displayName"] for account in accounts)
