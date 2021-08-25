import abc
import asyncio
import functools
import json
import os
import secrets
import tempfile
from abc import ABC
from dataclasses import dataclass
from os import fdopen
from typing import Any, Awaitable, Callable, Iterable, Mapping, Optional

import bmc
import botocore.exceptions
from aiobotocore.client import AioBaseClient
from yarl import URL

from platform_buckets_api.config import BucketsProviderType
from platform_buckets_api.storage import ProviderBucket, ProviderRole


class ProviderError(Exception):
    pass


class RoleExistsError(ProviderError):
    pass


class BucketExistsError(ProviderError):
    pass


class BucketDeleteError(ProviderError):
    pass


class ClusterNotFoundError(Exception):
    pass


@dataclass(frozen=True)
class BucketPermission:
    write: bool
    bucket_name: str
    is_prefix: bool = False

    def is_more_general_then(self, perm: "BucketPermission") -> bool:
        if not self.write and perm.write:
            return False
        if not self.is_prefix and perm.is_prefix:
            return False
        return perm.bucket_name.startswith(self.bucket_name)


class BucketProvider(abc.ABC):
    @abc.abstractmethod
    async def create_bucket(self, name: str) -> ProviderBucket:
        pass

    @abc.abstractmethod
    async def delete_bucket(self, name: str) -> None:
        pass

    @abc.abstractmethod
    async def get_bucket_credentials(
        self, name: str, write: bool, requester: str
    ) -> Mapping[str, str]:
        pass

    # Long term tokens methods

    @abc.abstractmethod
    async def create_role(self, username: str) -> ProviderRole:
        pass

    @abc.abstractmethod
    async def set_role_permissions(
        self, role: ProviderRole, permissions: Iterable[BucketPermission]
    ) -> None:
        pass

    @abc.abstractmethod
    async def delete_role(self, username: str) -> None:
        pass


class AWSLikeBucketProvider(BucketProvider, ABC):
    def __init__(
        self,
        s3_client: AioBaseClient,
        sts_client: AioBaseClient,
        s3_role_arn: str,
        session_duration_s: int = 3600,
    ):
        self._s3_client = s3_client
        self._sts_client = sts_client
        self._s3_role_arn = s3_role_arn
        self._session_duration_s = session_duration_s

    async def create_bucket(self, name: str) -> ProviderBucket:
        try:
            await self._s3_client.head_bucket(Bucket=name)
            raise BucketExistsError
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "404":
                pass
            else:
                raise
        try:
            await self._s3_client.create_bucket(
                Bucket=name,
                ACL="private",
            )
        except self._s3_client.exceptions.BucketAlreadyExists:
            raise BucketExistsError
        return ProviderBucket(
            name=name,
            provider_type=BucketsProviderType.AWS,
        )

    async def delete_bucket(self, name: str) -> None:
        try:
            await self._s3_client.delete_bucket(
                Bucket=name,
            )
        except botocore.exceptions.ClientError as e:
            raise BucketDeleteError(e.args[0])

    def _get_basic_credentials_data(self) -> Mapping[str, str]:
        return {
            "region_name": self._s3_client.meta.region_name,
            "endpoint_url": self._s3_client.meta.endpoint_url,
        }

    async def get_bucket_credentials(
        self, name: str, write: bool, requester: str
    ) -> Mapping[str, str]:
        policy_doc = self._permissions_to_policy_doc(
            [
                BucketPermission(
                    bucket_name=name,
                    write=write,
                )
            ]
        )
        res = await self._sts_client.assume_role(
            RoleArn=self._s3_role_arn,
            RoleSessionName=f"{name}-{requester}"[:58] + secrets.token_hex(3),
            Policy=json.dumps(policy_doc),
            DurationSeconds=self._session_duration_s,
        )
        return {
            **self._get_basic_credentials_data(),
            "access_key_id": res["Credentials"]["AccessKeyId"],
            "secret_access_key": res["Credentials"]["SecretAccessKey"],
            "session_token": res["Credentials"]["SessionToken"],
            "expiration": res["Credentials"]["Expiration"].isoformat(),
        }

    def _permissions_to_policy_doc(
        self, permissions: Iterable[BucketPermission]
    ) -> Mapping[str, Any]:
        def _bucket_arn(perm: BucketPermission) -> str:
            return f"arn:aws:s3:::{perm.bucket_name}" + ("*" if perm.is_prefix else "")

        statements = [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket"],
                "Resource": [_bucket_arn(perm) for perm in permissions],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [
                    f"{_bucket_arn(perm)}/*" for perm in permissions if not perm.write
                ],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                ],
                "Resource": [
                    f"{_bucket_arn(perm)}/*" for perm in permissions if perm.write
                ],
            },
        ]
        statements = [stat for stat in statements if stat["Resource"]]
        return {
            "Version": "2012-10-17",
            "Statement": statements,
        }


class AWSBucketProvider(AWSLikeBucketProvider):
    def __init__(
        self,
        s3_client: AioBaseClient,
        iam_client: AioBaseClient,
        sts_client: AioBaseClient,
        s3_role_arn: str,
        session_duration_s: int = 3600,
    ):
        super().__init__(s3_client, sts_client, s3_role_arn, session_duration_s)
        self._iam_client = iam_client

    async def create_role(self, username: str) -> ProviderRole:
        try:
            await self._iam_client.create_user(
                UserName=username,
                PermissionsBoundary="arn:aws:iam::aws:policy/AmazonS3FullAccess",
            )
        except self._iam_client.exceptions.EntityAlreadyExistsException:
            raise RoleExistsError(username)
        keys = (await self._iam_client.create_access_key(UserName=username))[
            "AccessKey"
        ]
        return ProviderRole(
            name=username,
            provider_type=BucketsProviderType.AWS,
            credentials={
                **self._get_basic_credentials_data(),
                "access_key_id": keys["AccessKeyId"],
                "secret_access_key": keys["SecretAccessKey"],
            },
        )

    async def set_role_permissions(
        self, role: ProviderRole, permissions: Iterable[BucketPermission]
    ) -> None:
        policy_doc = self._permissions_to_policy_doc(permissions)
        if not policy_doc["Statement"]:
            try:
                await self._iam_client.delete_user_policy(
                    UserName=role.name,
                    PolicyName=f"{role.name}-s3-policy",
                )
            except botocore.exceptions.ClientError:
                pass  # Used doesn't have any policy
        else:
            await self._iam_client.put_user_policy(
                UserName=role.name,
                PolicyName=f"{role.name}-s3-policy",
                PolicyDocument=json.dumps(policy_doc),
            )

    async def delete_role(self, username: str) -> None:
        try:
            await self._iam_client.delete_user_policy(
                UserName=username,
                PolicyName=f"{username}-s3-policy",
            )
        except botocore.exceptions.ClientError:
            pass  # Used doesn't have any policy
        try:
            resp = await self._iam_client.list_access_keys(
                UserName=username,
            )
            for key in resp["AccessKeyMetadata"]:
                await self._iam_client.delete_access_key(
                    UserName=username,
                    AccessKeyId=key["AccessKeyId"],
                )
        except botocore.exceptions.ClientError:
            pass  # Used doesn't have any policy
        await self._iam_client.delete_user(UserName=username)


class BMCWrapper:
    def __init__(self, url: URL, username: str, password: str):
        self._url = url
        self._username = username
        self._password = password
        self._target: Optional[str] = None

    def _make_wrapper(self, method: str) -> Callable[..., Awaitable[Any]]:
        real_func = getattr(bmc, method)

        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            if self._target:
                kwargs.setdefault("target", self._target)
            loop = asyncio.get_event_loop()
            res = await loop.run_in_executor(
                None, functools.partial(real_func, *args, **kwargs)
            )
            return res

        return _wrapper

    def __getattr__(self, item: str) -> Callable[..., Awaitable[Any]]:
        return self._make_wrapper(item)

    async def admin_user_list(self, *args: Any, **kwargs: Any) -> Any:
        resp = await self._make_wrapper("admin_user_list")(*args, **kwargs)
        # Fix list not always returns list
        if not isinstance(resp.content, list):
            resp.content = [resp.content]
        return resp

    async def __aenter__(self) -> "BMCWrapper":
        _target = "alias_" + secrets.token_hex(10)
        await self.config_host_add(
            alias=_target,
            url=str(self._url),
            username=self._username,
            password=self._password,
        )
        self._target = _target
        return self

    async def __aexit__(self, *args: Any) -> None:
        self._target = None


class MinioBucketProvider(AWSLikeBucketProvider):
    def __init__(
        self,
        s3_client: AioBaseClient,
        sts_client: AioBaseClient,
        mc: BMCWrapper,
        session_duration_s: int = 3600,
    ):
        super().__init__(
            s3_client,
            sts_client,
            s3_role_arn="arn:xxx:xxx:xxx:xxxx",
            session_duration_s=session_duration_s,
        )
        self._mc = mc

    async def create_role(self, username: str) -> ProviderRole:
        users = (await self._mc.admin_user_list()).content
        if username in {user["accessKey"] for user in users}:
            raise RoleExistsError(username)
        res = await self._mc.admin_user_add(
            username=username,
            password=secrets.token_hex(20),
        )
        return ProviderRole(
            name=username,
            provider_type=BucketsProviderType.MINIO,
            credentials={
                **self._get_basic_credentials_data(),
                "access_key_id": res.content["accessKey"],
                "secret_access_key": res.content["secretKey"],
            },
        )

    async def set_role_permissions(
        self, role: ProviderRole, permissions: Iterable[BucketPermission]
    ) -> None:
        policy_doc = self._permissions_to_policy_doc(permissions)
        policy_name = f"{role.name}-policy"
        if not policy_doc["Statement"]:
            try:
                await self._mc.admin_policy_remove(name=policy_name)
            except botocore.exceptions.ClientError:
                pass  # Used doesn't have any policy
        else:
            fd, path = tempfile.mkstemp()
            with fdopen(fd, "w") as f:
                f.write(json.dumps(policy_doc))
            await self._mc.admin_policy_add(
                name=policy_name,
                file=path,
            )
            os.unlink(path)
            await self._mc.admin_policy_set(name=policy_name, user=role.name)

    async def delete_role(self, username: str) -> None:
        await self._mc.admin_user_remove(username=username)
