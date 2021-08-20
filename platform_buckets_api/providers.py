import abc
import json
import secrets
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

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


class AWSBucketProvider(BucketProvider):
    def __init__(
        self,
        s3_client: AioBaseClient,
        iam_client: AioBaseClient,
        sts_client: AioBaseClient,
        s3_role_arn: str,
        session_duration_s: int = 3600,
    ):
        self._s3_client = s3_client
        self._iam_client = iam_client
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
            "access_key_id": res["Credentials"]["AccessKeyId"],
            "secret_access_key": res["Credentials"]["SecretAccessKey"],
            "session_token": res["Credentials"]["SessionToken"],
            "expiration": res["Credentials"]["Expiration"].isoformat(),
        }

    async def create_role(self, username: str) -> ProviderRole:
        try:
            await self._iam_client.create_user(
                UserName=username,
                PermissionsBoundary="arn:aws:iam::aws:policy/AmazonS3FullAccess",
            )
        except self._iam_client.exceptions.EntityAlreadyExistsException:
            raise RoleExistsError
        keys = (await self._iam_client.create_access_key(UserName=username))[
            "AccessKey"
        ]
        return ProviderRole(
            name=username,
            provider_type=BucketsProviderType.AWS,
            credentials={
                "access_key_id": keys["AccessKeyId"],
                "secret_access_key": keys["SecretAccessKey"],
            },
        )

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
                    "s3:DeleteObjects",
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
