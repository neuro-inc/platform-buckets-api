import base64
import json
import time
from contextlib import asynccontextmanager
from functools import partial
from typing import Any, AsyncIterator, List, Mapping

import google.cloud.exceptions
import googleapiclient.discovery
import pytest
from google.api_core.exceptions import Forbidden
from google.cloud.iam_credentials_v1 import IAMCredentialsAsyncClient
from google.cloud.storage import Bucket, Client as GSClient
from google.oauth2.credentials import Credentials
from google.oauth2.service_account import Credentials as SACredentials
from googleapiclient.errors import HttpError

from platform_buckets_api.providers import GoogleBucketProvider, run_in_executor
from platform_buckets_api.storage import ProviderBucket
from tests.integration.test_provider_base import (
    BUCKET_NAME_PREFIX,
    ROLE_NAME_PREFIX,
    BasicBucketClient,
    ProviderTestOption,
    TestProviderBase,
)


pytestmark = pytest.mark.asyncio


@run_in_executor
def gcs_bucket_exists(gs_client: GSClient, name: str) -> bool:
    try:
        return gs_client.bucket(name).exists()
    except google.cloud.exceptions.NotFound:
        return False


@run_in_executor
def gcs_role_exists(iam: Any, project_id: str, name: str) -> bool:
    try:
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
    def __init__(self, client: GSClient, bucket_name: str) -> None:
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
            client = GSClient(
                project=credentials["project"],
                credentials=Credentials(credentials["access_token"]),
            )
        else:
            credential = credentials["key_data"]
            key_json = json.loads(base64.b64decode(credential).decode())
            client = GSClient(
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
    def list_objects(self) -> List[str]:  # type: ignore
        return [entry.name for entry in self._client.list_blobs(self._bucket_name)]

    @run_in_executor
    def delete_object(self, key: str) -> None:  # type: ignore
        self._bucket_client.blob(key).delete()

    @run_in_executor
    def put_object(self, key: str, data: bytes) -> None:  # type: ignore
        self._bucket_client.blob(key).upload_from_string(data)


ACCOUNT_URL_ENV = "AZURE_STORAGE_ACCOUNT_URL"
ACCOUNT_CREDENTIAL_ENV = "AZURE_STORAGE_CREDENTIAL"

KEY_JSON: Any = {}


@pytest.fixture()
def sa_credentials() -> SACredentials:
    return SACredentials.from_service_account_info(info=KEY_JSON)


@pytest.fixture()
def project_id() -> str:
    return KEY_JSON["project_id"]


@pytest.fixture()
async def gcs_client(
    sa_credentials: SACredentials, project_id: str
) -> AsyncIterator[GSClient]:
    @run_in_executor
    def _cleanup_buckets(client: GSClient) -> None:
        for bucket in client.list_buckets():
            if bucket.name.startswith(BUCKET_NAME_PREFIX):
                client.bucket(bucket.name).delete(force=True)

    # if ACCOUNT_URL_ENV not in os.environ or ACCOUNT_CREDENTIAL_ENV not in os.environ:
    #     pytest.skip(
    #         f"Skipping Azure provider tests. Please set {ACCOUNT_URL_ENV}"
    #         f" and {ACCOUNT_CREDENTIAL_ENV} environ variables to enable tests"
    #     )

    client = GSClient(
        project=project_id,
        credentials=sa_credentials,
    )
    await _cleanup_buckets(client)
    yield client
    await _cleanup_buckets(client)
    client.close()


@pytest.fixture()
async def iam_client(
    sa_credentials: SACredentials, project_id: str
) -> AsyncIterator[Any]:
    @run_in_executor
    def _cleanup_sa(iam: Any) -> None:
        resp = (
            iam.projects()
            .serviceAccounts()
            .list(name=f"projects/{project_id}")
            .execute()
        )
        prefixes = [
            f"projects/{project_id}/serviceAccounts/{ROLE_NAME_PREFIX}",
            f"projects/{project_id}/serviceAccounts/bucket-api",
        ]
        for account in resp["accounts"]:
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


class TestGoogleProvider(TestProviderBase):
    __test__ = True

    @pytest.fixture()
    async def provider_option(
        self,
        gcs_client: GSClient,
        iam_client: Any,
        iam_client_2: IAMCredentialsAsyncClient,
        project_id: str,
    ) -> ProviderTestOption:
        return ProviderTestOption(
            type="gcs",
            provider=GoogleBucketProvider(
                gs_client=gcs_client,
                iam_client=iam_client,
                iam_client_2=iam_client_2,
            ),
            bucket_exists=partial(gcs_bucket_exists, gcs_client),
            make_client=GoogleBasicBucketClient.create,
            get_admin=lambda bucket: GoogleBasicBucketClient(gcs_client, bucket.name),
            role_exists=partial(gcs_role_exists, iam_client, project_id),
        )
