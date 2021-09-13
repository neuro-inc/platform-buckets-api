import os
from contextlib import asynccontextmanager
from functools import partial
from typing import AsyncIterator, List, Mapping

import pytest
from azure.storage.blob.aio import BlobServiceClient
from yarl import URL

from platform_buckets_api.providers import (
    AzureBucketProvider,
    _container_policies_as_dict,
)
from platform_buckets_api.storage import ProviderBucket
from tests.integration.test_provider_base import (
    BUCKET_NAME_PREFIX,
    BasicBucketClient,
    ProviderTestOption,
    TestProviderBase,
)


pytestmark = pytest.mark.asyncio


async def azure_bucket_exists(azure_blob_client: BlobServiceClient, name: str) -> bool:
    names = []
    async for container in azure_blob_client.list_containers():
        names.append(container.name)
    return name in names


async def azure_role_exists(azure_blob_client: BlobServiceClient, name: str) -> bool:
    container, policy_id = name.split("/", 1)
    container_client = azure_blob_client.get_container_client(container)
    policies = _container_policies_as_dict(
        (await container_client.get_container_access_policy())["signed_identifiers"]
    )
    return policy_id in policies


class AzureBasicBucketClient(BasicBucketClient):
    def __init__(self, client: BlobServiceClient, container_name: str) -> None:
        self._container_client = client.get_container_client(container_name)

    @classmethod
    @asynccontextmanager
    async def create(
        cls, bucket: ProviderBucket, credentials: Mapping[str, str]
    ) -> AsyncIterator["AzureBasicBucketClient"]:
        async with BlobServiceClient(
            account_url=credentials["storage_endpoint"],
            credential=credentials["sas_token"],
        ) as client:
            yield cls(client, bucket.name)

    async def read_object(self, key: str) -> bytes:
        blob_client = self._container_client.get_blob_client(key)
        downloader = await blob_client.download_blob()
        return await downloader.readall()

    async def list_objects(self) -> List[str]:
        keys = []
        async for blob in self._container_client.list_blobs():
            keys.append(blob.name)
        return keys

    async def delete_object(self, key: str) -> None:
        blob_client = self._container_client.get_blob_client(key)
        await blob_client.delete_blob()

    async def put_object(self, key: str, data: bytes) -> None:
        blob_client = self._container_client.get_blob_client(key)
        await blob_client.upload_blob(data)


ACCOUNT_URL_ENV = "AZURE_STORAGE_ACCOUNT_URL"
ACCOUNT_CREDENTIAL_ENV = "AZURE_STORAGE_CREDENTIAL"


@pytest.fixture()
async def azure_blob_client() -> AsyncIterator[BlobServiceClient]:
    async def _cleanup_containers(client: BlobServiceClient) -> None:
        async for container in client.list_containers():
            if container.name.startswith(BUCKET_NAME_PREFIX):
                await client.delete_container(container.name)

    if ACCOUNT_URL_ENV not in os.environ or ACCOUNT_CREDENTIAL_ENV not in os.environ:
        pytest.skip(
            f"Skipping Azure provider tests. Please set {ACCOUNT_URL_ENV}"
            f" and {ACCOUNT_CREDENTIAL_ENV} environ variables to enable tests"
        )

    async with BlobServiceClient(
        account_url=os.environ[ACCOUNT_URL_ENV],
        credential=os.environ[ACCOUNT_CREDENTIAL_ENV],
    ) as client:
        await _cleanup_containers(client)
        yield client
        await _cleanup_containers(client)


class TestAzureProvider(TestProviderBase):
    __test__ = True

    @pytest.fixture()
    async def provider_option(
        self, azure_blob_client: BlobServiceClient
    ) -> ProviderTestOption:
        return ProviderTestOption(
            type="azure",
            provider=AzureBucketProvider(
                storage_endpoint="https://neuromlops.blob.core.windows.net/",
                blob_client=azure_blob_client,
            ),
            bucket_exists=partial(azure_bucket_exists, azure_blob_client),
            make_client=AzureBasicBucketClient.create,
            get_admin=lambda bucket: AzureBasicBucketClient(
                azure_blob_client, bucket.name
            ),
            role_exists=partial(azure_role_exists, azure_blob_client),
            get_public_url=lambda bucket, key: URL(
                azure_blob_client.get_blob_client(bucket, key).url
            ),
        )
