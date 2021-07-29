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


class ClusterNotFoundError(Exception):
    pass


@dataclass(frozen=True)
class BucketPermission:
    bucket: ProviderBucket
    write: bool
    read: bool = True


class BucketProvider(abc.ABC):
    @abc.abstractmethod
    async def create_role(self, username: str) -> ProviderRole:
        pass

    @abc.abstractmethod
    async def create_bucket(self, name: str) -> ProviderBucket:
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
            user = (await self._iam_client.create_user(UserName=username))["User"]
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
            id=f"arn:aws:s3:::{name}",
            name=name,
            provider_type=BucketsProviderType.AWS,
        )

    async def set_role_permissions(
        self, role: ProviderRole, permissions: Iterable[BucketPermission]
    ) -> None:
        statements = []
        for perm in permissions:
            if perm.read:
                statements += [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:ListBucket"],
                        "Resource": perm.bucket.id,
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": f"{perm.bucket.id}/*",
                    },
                ]
            if perm.write:
                statements += [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:PutObject",
                            "s3:DeleteObject",
                            "s3:DeleteObjects",
                        ],
                        "Resource": f"{perm.bucket.id}/*",
                    },
                ]

        policy_document = {
            "Version": "2012-10-17",
            "Statement": statements,
        }
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
