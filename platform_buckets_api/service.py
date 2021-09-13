import hashlib
import logging
import secrets
from contextlib import asynccontextmanager
from dataclasses import replace
from typing import AsyncIterator, Iterable, List, Mapping, Optional
from uuid import uuid4

from yarl import URL

from platform_buckets_api.config import BucketsProviderType
from platform_buckets_api.permissions_service import PermissionsService
from platform_buckets_api.providers import (
    BucketNotExistsError,
    BucketPermission,
    BucketProvider,
    UserBucketOperations,
)
from platform_buckets_api.storage import (
    BaseBucket,
    BucketsStorage,
    CredentialsStorage,
    ImportedBucket,
    NotExistsError,
    PersistentCredentials,
    ProviderBucket,
    UserBucket,
)
from platform_buckets_api.utils import utc_now
from platform_buckets_api.utils.asyncio import asyncgeneratorcontextmanager


logger = logging.getLogger()


NEURO_BUCKET_PREFIX = "neuro-pl"


def make_owner_prefix(owner: str) -> str:
    hasher = hashlib.new("sha256")
    hasher.update(owner.encode("utf-8"))
    return f"{NEURO_BUCKET_PREFIX}-{hasher.hexdigest()[:10]}"


def make_bucket_name(name: Optional[str], owner: str) -> str:
    res = make_owner_prefix(owner) + f"-{owner}"
    if name is not None:
        res += f"-{name}"
    return res[:45] + secrets.token_hex(6)


def make_role_name(name: Optional[str], owner: str) -> str:
    res = f"bkt-user-{owner}"
    if name is not None:
        res += f"-{name}"
    return res[:24] + secrets.token_hex(3)


class BucketsService:
    def __init__(
        self,
        storage: BucketsStorage,
        bucket_provider: BucketProvider,
        permissions_service: PermissionsService,
    ) -> None:
        self._storage = storage
        self._permissions_service = permissions_service
        self._provider = bucket_provider

    async def create_bucket(self, owner: str, name: Optional[str] = None) -> UserBucket:
        real_name = make_bucket_name(name, owner)
        provider_bucket = await self._provider.create_bucket(real_name)
        bucket = UserBucket(
            id=f"bucket-{uuid4()}",
            name=name,
            owner=owner,
            provider_bucket=provider_bucket,
            created_at=utc_now(),
            public=False,
        )
        try:
            await self._storage.create_bucket(bucket)
        except Exception:
            await self._provider.delete_bucket(provider_bucket.name)
            raise
        return bucket

    async def import_bucket(
        self,
        owner: str,
        provider_bucket_name: str,
        provider_type: BucketsProviderType,
        credentials: Mapping[str, str],
        name: Optional[str] = None,
    ) -> ImportedBucket:
        bucket = ImportedBucket(
            id=f"bucket-{uuid4()}",
            name=name,
            owner=owner,
            provider_bucket=ProviderBucket(
                name=provider_bucket_name,
                provider_type=provider_type,
            ),
            created_at=utc_now(),
            credentials=credentials,
            public=False,
        )
        await self._storage.create_bucket(bucket)
        return bucket

    async def get_bucket(self, id: str) -> BaseBucket:
        return await self._storage.get_bucket(id)

    async def get_bucket_by_name(self, name: str, owner: str) -> BaseBucket:
        return await self._storage.get_bucket_by_name(name, owner)

    async def make_tmp_credentials(
        self, bucket: UserBucket, write: bool, requester: str
    ) -> Mapping[str, str]:
        return await self._provider.get_bucket_credentials(
            bucket.provider_bucket.name, write, requester
        )

    @asynccontextmanager
    async def _get_operations(
        self, bucket: BaseBucket
    ) -> AsyncIterator[UserBucketOperations]:
        if isinstance(bucket, ImportedBucket):
            async with UserBucketOperations.get_for_imported_bucket(bucket) as ops:
                yield ops
        else:
            yield self._provider

    async def sign_url_for_blob(
        self, bucket: BaseBucket, key: str, expires_in_sec: int = 3600
    ) -> URL:
        async with self._get_operations(bucket) as operations:
            return await operations.sign_url_for_blob(
                bucket_name=bucket.provider_bucket.name,
                key=key,
                expires_in_sec=expires_in_sec,
            )

    async def set_public_access(
        self, bucket: BaseBucket, public_access: bool
    ) -> BaseBucket:
        async with self._get_operations(bucket) as operations:
            await operations.set_public_access(
                bucket_name=bucket.provider_bucket.name,
                public_access=public_access,
            )
        bucket = replace(bucket, public=public_access)
        assert isinstance(bucket, (UserBucket, ImportedBucket))
        await self._storage.update_bucket(bucket)
        return bucket

    @asyncgeneratorcontextmanager
    async def get_user_buckets(self, owner: str) -> AsyncIterator[BaseBucket]:
        checker = await self._permissions_service.get_perms_checker(owner)
        async with self._storage.list_buckets() as it:
            async for bucket in it:
                if checker.can_read(bucket):
                    yield bucket

    async def delete_bucket(self, bucket_id: str) -> None:
        try:
            bucket = await self.get_bucket(bucket_id)
            if not bucket.imported:
                await self._provider.delete_bucket(bucket.provider_bucket.name)
            await self._storage.delete_bucket(bucket_id)
        except (NotExistsError, BucketNotExistsError):
            pass  # Bucket already removed or there was concurrent removal, just ignore


class PersistentCredentialsService:
    def __init__(
        self,
        bucket_provider: BucketProvider,
        storage: CredentialsStorage,
        buckets_service: BucketsService,
        permissions_service: PermissionsService,
    ):
        self._provider = bucket_provider
        self._storage = storage
        self._buckets_service = buckets_service
        self._permissions_service = permissions_service

    async def create_credentials(
        self,
        bucket_ids: Iterable[str],
        owner: str,
        name: Optional[str] = None,
        read_only: bool = False,
    ) -> PersistentCredentials:
        role_name = make_role_name(name, owner)
        permissions = await self._get_permissions(owner, bucket_ids, read_only)
        role = await self._provider.create_role(
            role_name, initial_permissions=permissions
        )

        credentials = PersistentCredentials(
            id=f"bucket-credentials-{uuid4()}",
            name=name,
            owner=owner,
            bucket_ids=list(bucket_ids),
            role=role,
            read_only=read_only,
        )
        try:
            await self._storage.create_credentials(credentials)
        except Exception:
            await self._provider.delete_role(role)
            raise
        return credentials

    async def get_credentials(self, credentials_id: str) -> PersistentCredentials:
        return await self._storage.get_credentials(credentials_id)

    async def get_credentials_by_name(
        self, name: str, owner: str
    ) -> PersistentCredentials:
        return await self._storage.get_credentials_by_name(name, owner)

    @asyncgeneratorcontextmanager
    async def list_user_credentials(
        self, owner: str
    ) -> AsyncIterator[PersistentCredentials]:
        async with self._storage.list_credentials(owner=owner) as it:
            async for credentials in it:
                yield credentials

    async def delete_credentials(self, credentials_id: str) -> None:
        try:
            credentials = await self.get_credentials(credentials_id)
            await self._provider.delete_role(credentials.role)
            await self._storage.delete_credentials(credentials_id)
        except NotExistsError:
            pass  # Already removed

    async def _sync_permissions(self, credentials: PersistentCredentials) -> None:
        permissions = await self._get_permissions(
            credentials.owner, credentials.bucket_ids, credentials.read_only
        )
        await self._provider.set_role_permissions(credentials.role, permissions)

    async def _get_permissions(
        self, owner: str, bucket_ids: Iterable[str], read_only: bool
    ) -> List[BucketPermission]:
        checker = await self._permissions_service.get_perms_checker(owner)
        buckets = [
            await self._buckets_service.get_bucket(bucket_id)
            for bucket_id in bucket_ids
        ]
        permissions: List[BucketPermission] = []
        for bucket in buckets:
            if checker.can_read(bucket):
                permissions.append(
                    BucketPermission(
                        bucket_name=bucket.provider_bucket.name,
                        write=not read_only and checker.can_write(bucket),
                    )
                )
        return permissions
