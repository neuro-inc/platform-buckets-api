import abc
import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import (
    AsyncContextManager,
    AsyncIterator,
    Awaitable,
    Callable,
    List,
    Mapping,
)

import pytest
from aiohttp import ClientSession
from yarl import URL

from platform_buckets_api.providers import (
    BucketExistsError,
    BucketNotExistsError,
    BucketPermission,
    BucketProvider,
    RoleExistsError,
    UserBucketOperations,
)
from platform_buckets_api.storage import ImportedBucket, ProviderBucket


pytestmark = pytest.mark.asyncio

BUCKET_NAME_PREFIX = "integration-tests-"
ROLE_NAME_PREFIX = "integration-tests-"


def _make_bucket_name() -> str:
    return BUCKET_NAME_PREFIX + secrets.token_hex(5)


def _make_role_name() -> str:
    return ROLE_NAME_PREFIX + secrets.token_hex(5)


class BasicBucketClient(abc.ABC):
    @abc.abstractmethod
    async def put_object(self, key: str, data: bytes) -> None:
        pass

    @abc.abstractmethod
    async def read_object(self, key: str) -> bytes:
        pass

    @abc.abstractmethod
    async def list_objects(self) -> List[str]:
        pass

    @abc.abstractmethod
    async def delete_object(self, key: str) -> None:
        pass


@dataclass()
class ProviderTestOption:
    type: str
    provider: BucketProvider
    bucket_exists: Callable[[str], Awaitable[bool]]
    make_client: Callable[
        [ProviderBucket, Mapping[str, str]], AsyncContextManager[BasicBucketClient]
    ]
    get_admin: Callable[[ProviderBucket], AsyncContextManager[BasicBucketClient]]
    role_exists: Callable[[str], Awaitable[bool]]
    get_public_url: Callable[[str, str], URL]
    credentials_for_imported: Mapping[str, str]


def as_admin_cm(
    creator_func: Callable[[ProviderBucket], BasicBucketClient]
) -> Callable[[ProviderBucket], AsyncContextManager[BasicBucketClient]]:
    @asynccontextmanager
    async def creator(bucket: ProviderBucket) -> AsyncIterator[BasicBucketClient]:
        yield creator_func(bucket)

    return creator


# Access checkers


async def _test_no_access(
    admin_client: BasicBucketClient,
    user_client: BasicBucketClient,
) -> None:
    data = b"\x01" * 1024
    key = secrets.token_hex(8)

    with pytest.raises(Exception):
        await user_client.put_object(key, data)

    await admin_client.put_object(key, data)

    with pytest.raises(Exception):
        await user_client.read_object(key)

    with pytest.raises(Exception):
        await user_client.list_objects()

    with pytest.raises(Exception):
        await user_client.delete_object(key)


async def _test_read_access(
    admin_client: BasicBucketClient,
    user_client: BasicBucketClient,
) -> None:
    data = b"\x01" * 1024
    key = "foo"

    with pytest.raises(Exception):
        await user_client.put_object(key, data)

    await admin_client.put_object(key, data)

    assert await user_client.read_object(key) == data

    assert key in await user_client.list_objects()

    with pytest.raises(Exception):
        await user_client.delete_object(key)


async def _test_write_access(
    user_client: BasicBucketClient,
) -> None:
    data = b"\x01" * 1024
    key = "foo"

    await user_client.put_object(key, data)

    assert await user_client.read_object(key) == data

    assert key in await user_client.list_objects()

    await user_client.delete_object(key)

    assert key not in await user_client.list_objects()


class TestProviderBase:
    __test__ = False

    async def test_bucket_create(self, provider_option: ProviderTestOption) -> None:
        name = _make_bucket_name()
        bucket = await provider_option.provider.create_bucket(name)
        assert bucket.name == name
        assert await provider_option.bucket_exists(name)

    async def test_bucket_duplicate_create(
        self,
        provider_option: ProviderTestOption,
    ) -> None:
        name = _make_bucket_name()
        await provider_option.provider.create_bucket(name)
        with pytest.raises(BucketExistsError):
            await provider_option.provider.create_bucket(name)

    async def test_bucket_delete(self, provider_option: ProviderTestOption) -> None:
        name = _make_bucket_name()
        bucket = await provider_option.provider.create_bucket(name)
        await provider_option.provider.delete_bucket(bucket.name)
        assert not await provider_option.bucket_exists(name)

    async def test_bucket_delete_unknown(
        self, provider_option: ProviderTestOption
    ) -> None:
        with pytest.raises(BucketNotExistsError):
            await provider_option.provider.delete_bucket(_make_bucket_name())

    async def test_bucket_credentials_write_access(
        self, provider_option: ProviderTestOption
    ) -> None:
        bucket = await provider_option.provider.create_bucket(_make_bucket_name())
        credentials = await provider_option.provider.get_bucket_credentials(
            bucket, write=True, requester="testing"
        )
        async with provider_option.make_client(bucket, credentials) as user_client:
            await _test_write_access(user_client)

    async def test_bucket_credentials_read_access(
        self, provider_option: ProviderTestOption
    ) -> None:
        return
        if provider_option.type == "aws":
            pytest.skip("Moto do not support embedding policies into token")
        bucket = await provider_option.provider.create_bucket(_make_bucket_name())
        credentials = await provider_option.provider.get_bucket_credentials(
            bucket, write=False, requester="testing"
        )
        async with provider_option.make_client(
            bucket, credentials
        ) as user_client, provider_option.get_admin(bucket) as admin:
            await _test_read_access(admin, user_client)

    async def test_signed_url_for_blob(
        self, provider_option: ProviderTestOption
    ) -> None:
        if provider_option.type == "aws":
            pytest.skip("Moto fails for signed url with 500")
        bucket = await provider_option.provider.create_bucket(_make_bucket_name())
        async with provider_option.get_admin(bucket) as admin_client:
            await admin_client.put_object("foo/bar", b"test data")
        url = await provider_option.provider.sign_url_for_blob(bucket, "foo/bar")
        async with ClientSession() as session:
            async with session.get(url) as resp:
                data = await resp.read()
                assert data == b"test data"

    async def test_public_access_to_bucket(
        self, provider_option: ProviderTestOption
    ) -> None:
        if provider_option.type == "aws":
            pytest.skip("Moto has bad support of this operation")
        bucket = await provider_option.provider.create_bucket(_make_bucket_name())
        async with provider_option.get_admin(bucket) as admin_client:
            await admin_client.put_object("blob1", b"blob data 1")
            await admin_client.put_object("blob2", b"blob data 2")
        await provider_option.provider.set_public_access(bucket.name, True)
        async with ClientSession() as session:
            url = provider_option.get_public_url(bucket.name, "blob1")
            async with session.get(url) as resp:
                data = await resp.read()
                assert data == b"blob data 1"
            url = provider_option.get_public_url(bucket.name, "blob2")
            async with session.get(url) as resp:
                data = await resp.read()
                assert data == b"blob data 2"

    async def test_bucket_make_public_for_imported_bucket(
        self, provider_option: ProviderTestOption
    ) -> None:
        if provider_option.type == "aws":
            pytest.skip("Moto fails with 500")

        name = _make_bucket_name()
        bucket = await provider_option.provider.create_bucket(name)
        async with provider_option.get_admin(bucket) as admin_client:
            await admin_client.put_object("blob1", b"blob data 1")
            await admin_client.put_object("blob2", b"blob data 2")

        async with UserBucketOperations.get_for_imported_bucket(
            ImportedBucket(
                id="not-important",
                created_at=datetime.now(timezone.utc),
                owner="user",
                name="not-important",
                public=False,
                provider_bucket=bucket,
                credentials=provider_option.credentials_for_imported,
            )
        ) as operations:
            await operations.set_public_access(bucket.name, True)
        async with ClientSession() as session:
            url = provider_option.get_public_url(bucket.name, "blob1")
            async with session.get(url) as resp:
                data = await resp.read()
                assert data == b"blob data 1"
            url = provider_option.get_public_url(bucket.name, "blob2")
            async with session.get(url) as resp:
                data = await resp.read()
                assert data == b"blob data 2"

    @pytest.fixture()
    async def sample_role_permissions(
        self, provider_option: ProviderTestOption
    ) -> List[BucketPermission]:
        bucket_name = _make_bucket_name()
        await provider_option.provider.create_bucket(bucket_name)
        return [
            BucketPermission(
                bucket_name=bucket_name,
                write=True,
            )
        ]

    async def test_role_create(
        self,
        provider_option: ProviderTestOption,
        sample_role_permissions: List[BucketPermission],
    ) -> None:
        name = _make_role_name()
        role = await provider_option.provider.create_role(name, sample_role_permissions)
        assert name in role.name
        assert await provider_option.role_exists(role.name)

    async def test_role_create_multiple(
        self,
        provider_option: ProviderTestOption,
        sample_role_permissions: List[BucketPermission],
    ) -> None:
        name1, name2 = _make_role_name(), _make_role_name()
        role1 = await provider_option.provider.create_role(
            name1, sample_role_permissions
        )
        role2 = await provider_option.provider.create_role(
            name2, sample_role_permissions
        )
        assert await provider_option.role_exists(role1.name)
        assert await provider_option.role_exists(role2.name)

    async def test_role_duplicate(
        self,
        provider_option: ProviderTestOption,
        sample_role_permissions: List[BucketPermission],
    ) -> None:
        name = _make_role_name()
        await provider_option.provider.create_role(name, sample_role_permissions)
        with pytest.raises(RoleExistsError):
            await provider_option.provider.create_role(name, sample_role_permissions)

    async def test_role_delete(
        self,
        provider_option: ProviderTestOption,
        sample_role_permissions: List[BucketPermission],
    ) -> None:
        name = _make_role_name()
        role = await provider_option.provider.create_role(name, sample_role_permissions)
        await provider_option.provider.delete_role(role)
        assert not await provider_option.role_exists(role.name)

    async def test_role_grant_bucket_write_access(
        self,
        provider_option: ProviderTestOption,
    ) -> None:
        bucket = await provider_option.provider.create_bucket(_make_bucket_name())
        permissions = [
            BucketPermission(
                bucket_name=bucket.name,
                write=True,
            )
        ]
        role = await provider_option.provider.create_role(
            _make_role_name(), permissions
        )
        async with provider_option.make_client(bucket, role.credentials) as user_client:
            await _test_write_access(user_client)

    async def test_role_grant_bucket_read_only_access(
        self,
        provider_option: ProviderTestOption,
    ) -> None:
        return
        bucket = await provider_option.provider.create_bucket(_make_bucket_name())
        permissions = [
            BucketPermission(
                bucket_name=bucket.name,
                write=False,
            )
        ]
        role = await provider_option.provider.create_role(
            _make_role_name(), permissions
        )
        async with provider_option.make_client(
            bucket, role.credentials
        ) as user_client, provider_option.get_admin(bucket) as admin:
            await _test_read_access(admin, user_client)

    async def test_role_grant_access_multiple_buckets(
        self,
        provider_option: ProviderTestOption,
    ) -> None:
        if provider_option.type == "azure":
            pytest.skip("Azure provider do not support multiple buckets roles")

        bucket1 = await provider_option.provider.create_bucket(_make_bucket_name())
        permissions = [
            BucketPermission(
                bucket_name=bucket1.name,
                write=True,
            )
        ]
        role = await provider_option.provider.create_role(
            _make_role_name(), permissions
        )
        async with provider_option.make_client(
            bucket1, role.credentials
        ) as user_client:
            await _test_write_access(user_client)

        bucket2 = await provider_option.provider.create_bucket(_make_bucket_name())
        await provider_option.provider.set_role_permissions(
            role,
            [
                BucketPermission(
                    bucket_name=bucket1.name,
                    write=True,
                ),
                BucketPermission(
                    bucket_name=bucket2.name,
                    write=True,
                ),
            ],
        )
        async with provider_option.make_client(
            bucket1, role.credentials
        ) as user_client:
            await _test_write_access(user_client)
        async with provider_option.make_client(
            bucket2, role.credentials
        ) as user_client:
            await _test_write_access(user_client)

    async def test_role_downgrade_access(
        self,
        provider_option: ProviderTestOption,
    ) -> None:
        bucket = await provider_option.provider.create_bucket(_make_bucket_name())
        permissions = [
            BucketPermission(
                bucket_name=bucket.name,
                write=True,
            )
        ]
        role = await provider_option.provider.create_role(
            _make_role_name(), permissions
        )
        async with provider_option.make_client(bucket, role.credentials) as user_client:
            await _test_write_access(user_client)
        await provider_option.provider.set_role_permissions(
            role,
            [
                BucketPermission(
                    bucket_name=bucket.name,
                    write=False,
                ),
            ],
        )
        async with provider_option.make_client(
            bucket, role.credentials
        ) as user_client, provider_option.get_admin(bucket) as admin:
            await _test_read_access(admin, user_client)
        await provider_option.provider.set_role_permissions(
            role,
            [],
        )
        async with provider_option.make_client(
            bucket, role.credentials
        ) as user_client, provider_option.get_admin(bucket) as admin:
            await _test_no_access(admin, user_client)
