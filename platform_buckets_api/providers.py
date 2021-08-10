import abc
import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping

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
        bucket_to_statements: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
        for perm in permissions:
            if perm.read:
                bucket_to_statements[perm.bucket.name] += [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:ListBucket"],
                        "Resource": f"arn:aws:s3:::{perm.bucket.name}",
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": f"arn:aws:s3:::{perm.bucket.name}/*",
                    },
                ]
            if perm.write:
                bucket_to_statements[perm.bucket.name] += [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:PutObject",
                            "s3:DeleteObject",
                            "s3:DeleteObjects",
                        ],
                        "Resource": f"arn:aws:s3:::{perm.bucket.name}/*",
                    },
                ]

        policies = {
            f"{bucket_name}-bucket-policy": {
                "Version": "2012-10-17",
                "Statement": statements,
            }
            for bucket_name, statements in bucket_to_statements.items()
        }
        paginator = self._iam_client.get_paginator("list_user_policies")
        async for result in paginator.paginate(UserName=role.id):
            for name in result["PolicyNames"]:
                if name not in policies:
                    try:
                        await self._iam_client.delete_user_policy(
                            UserName=role.id,
                            PolicyName=name,
                        )
                    except botocore.exceptions.ClientError:
                        pass  # Used doesn't have any policy

        for policy_name, doc in policies.items():
            await self._iam_client.put_user_policy(
                UserName=role.id,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(doc),
            )
