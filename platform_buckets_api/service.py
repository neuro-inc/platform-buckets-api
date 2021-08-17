import hashlib
import logging
import secrets
from typing import AsyncIterator, Iterable, List, Mapping, Optional
from uuid import uuid4

from platform_buckets_api.permissions_service import PermissionsService
from platform_buckets_api.providers import BucketPermission, BucketProvider
from platform_buckets_api.storage import (
    BucketsStorage,
    CredentialsStorage,
    PersistentCredentials,
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
    res = f"neuro-bucketuser-{owner}"
    if name is not None:
        res += f"-{name}"
    return res + secrets.token_hex(5)


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
        )
        try:
            await self._storage.create_bucket(bucket)
        except Exception:
            await self._provider.delete_bucket(provider_bucket.name)
            raise
        return bucket

    async def get_bucket(self, id: str) -> UserBucket:
        return await self._storage.get_bucket(id)

    async def get_bucket_by_name(self, name: str, owner: str) -> UserBucket:
        return await self._storage.get_bucket_by_name(name, owner)

    async def make_tmp_credentials(
        self, bucket: UserBucket, write: bool, requester: str
    ) -> Mapping[str, str]:
        return await self._provider.get_bucket_credentials(
            bucket.provider_bucket.name, write, requester
        )

    @asyncgeneratorcontextmanager
    async def get_user_buckets(self, owner: str) -> AsyncIterator[UserBucket]:
        checker = await self._permissions_service.get_perms_checker(owner)
        async with self._storage.list_buckets() as it:
            async for bucket in it:
                if checker.can_read(bucket):
                    yield bucket

    async def delete_bucket(self, bucket_id: str) -> None:
        bucket = await self.get_bucket(bucket_id)
        await self._provider.delete_bucket(bucket.provider_bucket.name)
        await self._storage.delete_bucket(bucket_id)


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
        self, bucket_ids: Iterable[str], owner: str, name: Optional[str] = None
    ) -> PersistentCredentials:
        role_name = make_role_name(name, owner)
        role = await self._provider.create_role(role_name)

        credentials = PersistentCredentials(
            id=f"bucket-credentials-{uuid4()}",
            name=name,
            owner=owner,
            bucket_ids=list(bucket_ids),
            role=role,
        )
        try:
            await self._storage.create_credentials(credentials)
        except Exception:
            await self._provider.delete_role(role.name)
            raise
        await self._sync_permissions(credentials)
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
        credentials = await self.get_credentials(credentials_id)
        await self._provider.delete_role(credentials.role.name)
        await self._storage.delete_credentials(credentials_id)

    async def _sync_permissions(self, credentials: PersistentCredentials) -> None:

        checker = await self._permissions_service.get_perms_checker(credentials.owner)
        buckets = [
            await self._buckets_service.get_bucket(bucket_id)
            for bucket_id in credentials.bucket_ids
        ]

        permissions: List[BucketPermission] = []

        def _append(perm: BucketPermission) -> None:
            if not any(
                (
                    (
                        perm.is_prefix
                        and bucket.provider_bucket.name.startswith(perm.bucket_name)
                    )
                    or (perm.bucket_name == bucket.provider_bucket.name)
                )
                for bucket in buckets
            ):
                return  # Permission has no effect on buckets
            if not any(
                existing_perm.is_more_general_then(perm)
                for existing_perm in permissions
            ):
                permissions.append(perm)

        if checker.can_write_any():
            _append(
                BucketPermission(
                    write=True, bucket_name=NEURO_BUCKET_PREFIX, is_prefix=True
                )
            )
        if checker.can_read_any():
            _append(
                BucketPermission(
                    write=False, bucket_name=NEURO_BUCKET_PREFIX, is_prefix=True
                )
            )
        for username in checker.write_access_for_owner_by():
            _append(
                BucketPermission(
                    write=True,
                    bucket_name=make_owner_prefix(username),
                    is_prefix=True,
                )
            )
        for username in checker.read_access_for_owner_by():
            _append(
                BucketPermission(
                    write=False,
                    bucket_name=make_owner_prefix(username),
                    is_prefix=True,
                )
            )
        for bucket in buckets:
            if checker.can_read(bucket):
                _append(
                    BucketPermission(
                        bucket_name=bucket.provider_bucket.name,
                        write=checker.can_write(bucket),
                    )
                )
        await self._provider.set_role_permissions(credentials.role, permissions)
