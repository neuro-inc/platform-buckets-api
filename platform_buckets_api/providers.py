import abc
import json
from dataclasses import dataclass
from typing import Iterable

import botocore.exceptions
from aiobotocore.client import AioBaseClient

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
    async def create_role(self, username: str) -> ProviderRole:
        pass

    @abc.abstractmethod
    async def create_bucket(self, name: str) -> ProviderBucket:
        pass

    @abc.abstractmethod
    async def delete_bucket(self, name: str) -> None:
        pass

    @abc.abstractmethod
    async def set_role_permissions(
        self, role: ProviderRole, permissions: Iterable[BucketPermission]
    ) -> None:
        pass


class AWSBucketProvider(BucketProvider):
    def __init__(self, s3_client: AioBaseClient, iam_client: AioBaseClient):
        self._s3_client = s3_client
        self._iam_client = iam_client

    async def create_role(self, username: str) -> ProviderRole:
        try:
            user = (
                await self._iam_client.create_user(
                    UserName=username,
                    PermissionsBoundary="arn:aws:iam::aws:policy/AmazonS3FullAccess",
                )
            )["User"]
        except self._iam_client.exceptions.EntityAlreadyExistsException:
            raise RoleExistsError
        keys = (await self._iam_client.create_access_key(UserName=username))[
            "AccessKey"
        ]
        return ProviderRole(
            id=user["UserName"],
            provider_type=BucketsProviderType.AWS,
            credentials={
                "access_key_id": keys["AccessKeyId"],
                "secret_access_key": keys["SecretAccessKey"],
            },
        )

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

    async def set_role_permissions(
        self, role: ProviderRole, permissions: Iterable[BucketPermission]
    ) -> None:
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
                    "s3:DeleteObjects",
                ],
                "Resource": [
                    f"{_bucket_arn(perm)}/*" for perm in permissions if perm.write
                ],
            },
        ]
        statements = [stat for stat in statements if stat["Resource"]]
        policy_document = {
            "Version": "2012-10-17",
            "Statement": statements,
        }
        print(policy_document)
        if not statements:
            try:
                await self._iam_client.delete_user_policy(
                    UserName=role.id,
                    PolicyName=f"{role.id}-s3-policy",
                )
            except botocore.exceptions.ClientError:
                pass  # Used doesn't have any policy
        else:
            await self._iam_client.put_user_policy(
                UserName=role.id,
                PolicyName=f"{role.id}-s3-policy",
                PolicyDocument=json.dumps(policy_document),
            )
