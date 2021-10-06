import abc
import asyncio
import base64
import datetime
import functools
import hashlib
import json
import os
import secrets
import tempfile
import typing
from abc import ABC
from contextlib import asynccontextmanager
from dataclasses import dataclass
from os import fdopen
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
)

import aiobotocore
import aiohttp
import bmc
import botocore.exceptions
import google.cloud.exceptions
from aiobotocore.client import AioBaseClient
from aiobotocore.credentials import AioCredentials
from aiohttp import ClientError
from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.storage.blob import (
    AccessPolicy,
    BlobSasPermissions,
    ContainerSasPermissions,
    PublicAccess,
    generate_blob_sas,
    generate_container_sas,
)
from azure.storage.blob.aio import BlobClient, BlobServiceClient
from bmc._utils import Command
from google.api_core.iam import Policy
from google.cloud.iam_credentials import IAMCredentialsAsyncClient
from google.cloud.storage import Client as GCSClient
from google.cloud.storage.constants import (
    PUBLIC_ACCESS_PREVENTION_ENFORCED,
    PUBLIC_ACCESS_PREVENTION_UNSPECIFIED,
)
from google.oauth2.service_account import Credentials as SACredentials
from googleapiclient.errors import HttpError as GoogleHttpError
from yarl import URL

from platform_buckets_api.config import BucketsProviderType
from platform_buckets_api.storage import ImportedBucket, ProviderBucket, ProviderRole


class ProviderError(Exception):
    pass


class RoleExistsError(ProviderError):
    pass


class BucketExistsError(ProviderError):
    pass


class BucketNotExistsError(ProviderError):
    pass


class ClusterNotFoundError(Exception):
    pass


@dataclass(frozen=True)
class BucketPermission:
    write: bool
    bucket_name: str


class UserBucketOperations(abc.ABC):
    @abc.abstractmethod
    async def set_public_access(
        self,
        bucket_name: str,
        public_access: bool,
    ) -> None:
        pass

    @abc.abstractmethod
    async def sign_url_for_blob(
        self, bucket: ProviderBucket, key: str, expires_in_sec: int = 3600
    ) -> URL:
        pass

    @staticmethod
    @asynccontextmanager
    async def get_for_imported_bucket(
        bucket: ImportedBucket,
    ) -> AsyncIterator["UserBucketOperations"]:
        provider_type = bucket.provider_bucket.provider_type
        if provider_type == BucketsProviderType.AWS:
            session = aiobotocore.get_session()
            session._credentials = AioCredentials(
                access_key=bucket.credentials["access_key_id"],
                secret_key=bucket.credentials["secret_access_key"],
            )
            async with session.create_client(
                "s3",
                endpoint_url=bucket.credentials.get("endpoint_url"),
                region_name=bucket.credentials.get("region_name"),
            ) as client:
                yield AWSLikeUserBucketOperations(client)
        elif provider_type == BucketsProviderType.AZURE:
            async with BlobServiceClient(
                account_url=bucket.credentials["storage_endpoint"],
                credential=bucket.credentials["credential"],
            ) as client:
                yield AzureUserBucketOperations(client)
        elif provider_type == BucketsProviderType.GCP:
            key_raw = bucket.credentials["key_data"]
            key_json = json.loads(base64.b64decode(key_raw).decode())
            client = GCSClient(
                project=key_json["project_id"],
                credentials=SACredentials.from_service_account_info(key_json),
            )
            yield GoogleUserBucketOperations(client)
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, client.close)


class BucketProvider(UserBucketOperations, abc.ABC):
    @abc.abstractmethod
    async def create_bucket(self, name: str) -> ProviderBucket:
        pass

    @abc.abstractmethod
    async def delete_bucket(self, name: str) -> None:
        pass

    @abc.abstractmethod
    async def get_bucket_credentials(
        self, bucket: ProviderBucket, write: bool, requester: str
    ) -> Mapping[str, str]:
        pass

    # Long term tokens methods

    @abc.abstractmethod
    async def create_role(
        self, username: str, initial_permissions: Iterable[BucketPermission]
    ) -> ProviderRole:
        pass

    @abc.abstractmethod
    async def set_role_permissions(
        self, role: ProviderRole, permissions: Iterable[BucketPermission]
    ) -> None:
        pass

    @abc.abstractmethod
    async def delete_role(self, role: ProviderRole) -> None:
        pass


class AWSLikeUserBucketOperations(UserBucketOperations, ABC):
    def __init__(self, s3_client: AioBaseClient):
        self._s3_client = s3_client

    async def sign_url_for_blob(
        self, bucket: ProviderBucket, key: str, expires_in_sec: int = 3600
    ) -> URL:
        if expires_in_sec > datetime.timedelta(days=7).total_seconds():
            raise ValueError("S3 do not support signed urls for more then 7 days")
        return URL(
            await self._s3_client.generate_presigned_url(
                ClientMethod="get_object",
                Params={"Bucket": bucket.name, "Key": key},
                ExpiresIn=expires_in_sec,
            )
        )

    async def set_public_access(self, bucket_name: str, public_access: bool) -> None:
        policy: Dict[str, Any]
        policy_exists = False
        try:
            policy_raw = (
                await self._s3_client.get_bucket_policy(
                    Bucket=bucket_name,
                )
            )["Policy"]
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                raise
            policy = {"Version": "2012-10-17", "Statement": []}
        else:
            policy_exists = True
            policy = json.loads(policy_raw)

        policy["Statement"] = [
            statement
            for statement in policy["Statement"]
            if "neuro-public-access" not in statement["Sid"]
        ]
        if public_access:
            policy["Statement"] += [
                {
                    "Sid": "neuro-public-access-get-objects",
                    "Action": [
                        "s3:GetObject",
                    ],
                    "Effect": "Allow",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    "Principal": "*",
                },
                {
                    "Sid": "neuro-public-access-get-objects",
                    "Action": [
                        "s3:ListBucket",
                    ],
                    "Effect": "Allow",
                    "Resource": f"arn:aws:s3:::{bucket_name}",
                    "Principal": "*",
                },
            ]
        if policy["Statement"]:
            await self._s3_client.put_bucket_policy(
                Bucket=bucket_name, Policy=json.dumps(policy)
            )
        elif policy_exists:
            await self._s3_client.delete_bucket_policy(
                Bucket=bucket_name,
            )


class AWSLikeBucketProvider(BucketProvider, ABC):
    def __init__(
        self,
        s3_client: AioBaseClient,
        sts_client: AioBaseClient,
        s3_role_arn: str,
        session_duration_s: int = 3600,
        public_url: Optional[URL] = None,
    ):
        self._s3_client = s3_client
        self._sts_client = sts_client
        self._s3_role_arn = s3_role_arn
        self._session_duration_s = session_duration_s
        self._public_url = (
            str(public_url) if public_url else self._s3_client.meta.endpoint_url
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
        except self._s3_client.exceptions.NoSuchBucket:
            raise BucketNotExistsError(name)

    def _get_basic_credentials_data(self) -> Mapping[str, str]:
        return {
            "region_name": self._s3_client.meta.region_name,
            "endpoint_url": self._public_url,
        }

    async def get_bucket_credentials(
        self, bucket: ProviderBucket, write: bool, requester: str
    ) -> Mapping[str, str]:
        policy_doc = self._permissions_to_policy_doc(
            [
                BucketPermission(
                    bucket_name=bucket.name,
                    write=write,
                )
            ]
        )
        res = await self._sts_client.assume_role(
            RoleArn=self._s3_role_arn,
            RoleSessionName=f"{bucket.name}-{requester}"[:58] + secrets.token_hex(3),
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
            return f"arn:aws:s3:::{perm.bucket_name}"

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


class AWSBucketProvider(AWSLikeBucketProvider, AWSLikeUserBucketOperations):
    def __init__(
        self,
        s3_client: AioBaseClient,
        iam_client: AioBaseClient,
        sts_client: AioBaseClient,
        s3_role_arn: str,
        session_duration_s: int = 3600,
        permissions_boundary: str = "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    ):
        super().__init__(s3_client, sts_client, s3_role_arn, session_duration_s)
        self._iam_client = iam_client
        self._permissions_boundary = permissions_boundary

    async def create_role(
        self, username: str, initial_permissions: Iterable[BucketPermission]
    ) -> ProviderRole:
        try:
            await self._iam_client.create_user(
                UserName=username,
                PermissionsBoundary=self._permissions_boundary,
            )
        except self._iam_client.exceptions.EntityAlreadyExistsException:
            raise RoleExistsError(username)
        keys = (await self._iam_client.create_access_key(UserName=username))[
            "AccessKey"
        ]
        role = ProviderRole(
            name=username,
            provider_type=BucketsProviderType.AWS,
            credentials={
                **self._get_basic_credentials_data(),
                "access_key_id": keys["AccessKeyId"],
                "secret_access_key": keys["SecretAccessKey"],
            },
        )
        if initial_permissions:
            await self.set_role_permissions(role, initial_permissions)
        return role

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

    async def delete_role(self, role: ProviderRole) -> None:
        try:
            await self._iam_client.delete_user_policy(
                UserName=role.name,
                PolicyName=f"{role.name}-s3-policy",
            )
        except botocore.exceptions.ClientError:
            pass  # Used doesn't have any policy
        try:
            resp = await self._iam_client.list_access_keys(
                UserName=role.name,
            )
            for key in resp["AccessKeyMetadata"]:
                await self._iam_client.delete_access_key(
                    UserName=role.name,
                    AccessKeyId=key["AccessKeyId"],
                )
        except botocore.exceptions.ClientError:
            pass  # Used doesn't have any policy
        await self._iam_client.delete_user(UserName=role.name)


class BMCWrapper:
    def __init__(self, url: URL, username: str, password: str):
        self._url = url
        self._username = username
        self._password = password
        self._target: Optional[str] = None

    def _make_wrapper(
        self, real_func: Callable[..., Any]
    ) -> Callable[..., Awaitable[Any]]:
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
        real_func = getattr(bmc, item)
        return self._make_wrapper(real_func)

    async def admin_user_list(self, *args: Any, **kwargs: Any) -> Any:
        resp = await self._make_wrapper(bmc.admin_user_list)(*args, **kwargs)
        # Fix list not always returns list
        if not isinstance(resp.content, list):
            resp.content = [resp.content]
        return resp

    async def policy_set(self, *, permission: str, bucket_name: str) -> Any:
        cmd = Command("mc {flags} policy set {permission} {target}")
        target = f"{self._target}/{bucket_name}"
        return await self._make_wrapper(cmd)(permission=permission, target=target)

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


class MinioBucketProvider(AWSLikeBucketProvider, AWSLikeUserBucketOperations):
    def __init__(
        self,
        s3_client: AioBaseClient,
        sts_client: AioBaseClient,
        mc: BMCWrapper,
        session_duration_s: int = 3600,
        public_url: Optional[URL] = None,
    ):
        super().__init__(
            s3_client,
            sts_client,
            s3_role_arn="arn:xxx:xxx:xxx:xxxx",
            session_duration_s=session_duration_s,
            public_url=public_url,
        )
        self._mc = mc

    async def create_role(
        self, username: str, initial_permissions: Iterable[BucketPermission]
    ) -> ProviderRole:
        users = (await self._mc.admin_user_list()).content
        if username in {user["accessKey"] for user in users}:
            raise RoleExistsError(username)
        res = await self._mc.admin_user_add(
            username=username,
            password=secrets.token_hex(20),
        )
        role = ProviderRole(
            name=username,
            provider_type=BucketsProviderType.MINIO,
            credentials={
                **self._get_basic_credentials_data(),
                "access_key_id": res.content["accessKey"],
                "secret_access_key": res.content["secretKey"],
            },
        )
        if initial_permissions:
            await self.set_role_permissions(role, initial_permissions)
        return role

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

    async def delete_role(self, role: ProviderRole) -> None:
        await self._mc.admin_user_remove(username=role.name)


def _container_policies_as_dict(policies: List[Any]) -> Dict[str, Any]:
    return {entry.id: entry.access_policy for entry in policies}


class AzureUserBucketOperations(UserBucketOperations):
    def __init__(self, blob_client: BlobServiceClient):
        self._blob_client = blob_client

    async def set_public_access(self, bucket_name: str, public_access: bool) -> None:
        container_client = self._blob_client.get_container_client(bucket_name)
        policies = _container_policies_as_dict(
            (await container_client.get_container_access_policy())["signed_identifiers"]
        )
        await container_client.set_container_access_policy(
            signed_identifiers=policies,
            public_access=PublicAccess.Container,
        )

    async def sign_url_for_blob(
        self, bucket: ProviderBucket, key: str, expires_in_sec: int = 3600
    ) -> URL:
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            seconds=expires_in_sec
        )
        token: str = generate_blob_sas(
            account_name=self._blob_client.account_name,
            blob_name=key,
            container_name=bucket.name,
            account_key=self._blob_client.credential.account_key,
            permission=BlobSasPermissions.from_string("r"),
            expiry=expiry,
        )
        return URL(
            BlobClient.from_blob_url(
                self._blob_client.get_blob_client(bucket.name, key).url,
                credential=token,
            ).url
        )


class AzureBucketProvider(BucketProvider, AzureUserBucketOperations):
    def __init__(self, storage_endpoint: str, blob_client: BlobServiceClient):
        super().__init__(blob_client)
        self._storage_endpoint = storage_endpoint

    async def create_bucket(self, name: str) -> ProviderBucket:
        try:
            await self._blob_client.create_container(name)
        except ResourceExistsError:
            raise BucketExistsError(name)
        return ProviderBucket(name=name, provider_type=BucketsProviderType.AZURE)

    async def delete_bucket(self, name: str) -> None:
        try:
            await self._blob_client.delete_container(name)
        except ResourceNotFoundError:
            raise BucketNotExistsError(name)

    def _make_sas_permissions(self, write: bool) -> ContainerSasPermissions:
        if write:
            return ContainerSasPermissions(
                read=True,
                list=True,
                write=True,
                delete=True,
                delete_previous_version=True,
                tag=True,
            )
        else:
            return ContainerSasPermissions(
                read=True,
                list=True,
            )

    async def get_bucket_credentials(
        self, bucket: ProviderBucket, write: bool, requester: str
    ) -> Mapping[str, str]:
        expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            hours=1
        )
        token: str = generate_container_sas(
            account_name=self._blob_client.account_name,
            container_name=bucket.name,
            account_key=self._blob_client.credential.account_key,
            permission=self._make_sas_permissions(write),
            expiry=expiry,
        )
        return {
            "storage_endpoint": self._storage_endpoint,
            "sas_token": token,
            "expiry": expiry.isoformat(),
        }

    async def create_role(
        self, username: str, initial_permissions: Iterable[BucketPermission]
    ) -> ProviderRole:
        if not initial_permissions:
            raise NotImplementedError(
                "Azure provider cannot create role without initial_permissions"
            )
        initial_permissions = list(initial_permissions)
        if len(initial_permissions) > 1:
            raise NotImplementedError(
                "Azure provider only supports one bucket per credentials"
            )
        permission = initial_permissions[0]
        container_client = self._blob_client.get_container_client(
            permission.bucket_name
        )
        access_policy = await container_client.get_container_access_policy()
        policies = _container_policies_as_dict(access_policy["signed_identifiers"])
        if len(policies) == 5:
            raise ValueError(
                f"Azure container {permission.bucket_name} already has 5 SAP entries, "
                f"generation of new token isn't possible"
            )
        if username in policies:
            raise RoleExistsError(username)
        policies[username] = AccessPolicy(
            permission=self._make_sas_permissions(permission.write),
            start=datetime.datetime.utcnow() - datetime.timedelta(hours=1),
            expiry=datetime.datetime.utcnow()
            + datetime.timedelta(days=365 * 100),  # Permanent
        )
        await container_client.set_container_access_policy(
            signed_identifiers=policies,
            public_access=access_policy["public_access"],
        )
        sas_token = generate_container_sas(
            container_client.account_name,
            container_client.container_name,
            account_key=container_client.credential.account_key,
            policy_id=username,
        )
        return ProviderRole(
            provider_type=BucketsProviderType.AZURE,
            name=f"{permission.bucket_name}/{username}",
            credentials={
                "storage_endpoint": self._storage_endpoint,
                "sas_token": sas_token,
            },
        )

    async def set_role_permissions(
        self, role: ProviderRole, permissions: Iterable[BucketPermission]
    ) -> None:
        permissions = list(permissions)
        if len(permissions) > 1:
            raise NotImplementedError(
                "Azure provider only supports one bucket per credentials"
            )
        container_name, policy_id = role.name.split("/", 1)
        container_client = self._blob_client.get_container_client(container_name)
        policies = _container_policies_as_dict(
            (await container_client.get_container_access_policy())["signed_identifiers"]
        )
        if len(permissions) == 0:
            policies.pop(policy_id, None)
            await container_client.set_container_access_policy(
                signed_identifiers=policies
            )
        else:
            permission = permissions[0]
            if permission.bucket_name != container_name:
                raise NotImplementedError(
                    "Azure provider role cannot be re-applied to another bucket"
                )
            policies[policy_id] = AccessPolicy(
                permission=self._make_sas_permissions(permission.write),
                start=datetime.datetime.utcnow() - datetime.timedelta(hours=1),
                expiry=datetime.datetime.utcnow()
                + datetime.timedelta(days=365 * 100),  # Permanent
            )
            await container_client.set_container_access_policy(
                signed_identifiers=policies
            )

    async def delete_role(self, role: ProviderRole) -> None:
        await self.set_role_permissions(role, ())


R = typing.TypeVar("R")


def run_in_executor(func: Callable[..., R]) -> Callable[..., Awaitable[R]]:
    async def _wrapper(*args: Any, **kwargs: Any) -> R:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, functools.partial(func, *args, **kwargs)
        )

    return _wrapper


class GoogleUserBucketOperations(UserBucketOperations):
    def __init__(
        self,
        gcs_client: GCSClient,
    ):
        self._gcs_client = gcs_client

    async def set_public_access(self, bucket_name: str, public_access: bool) -> None:
        await self._set_public_access(bucket_name, public_access)

    @run_in_executor
    def _set_public_access(self, bucket_name: str, public_access: bool) -> None:
        bucket = self._gcs_client.bucket(bucket_name)

        if public_access:
            bucket.iam_configuration.public_access_prevention = (
                PUBLIC_ACCESS_PREVENTION_UNSPECIFIED
            )
            bucket.patch()
        else:
            bucket.iam_configuration.public_access_prevention = (
                PUBLIC_ACCESS_PREVENTION_ENFORCED
            )
            bucket.patch()

        policy = bucket.get_iam_policy(requested_policy_version=3)
        public_read_entry = {
            "role": "roles/storage.objectViewer",
            "members": {"allUsers"},
        }
        policy.bindings = [
            entry for entry in policy.bindings if entry != public_read_entry
        ]
        if public_access:
            policy.bindings.append(public_read_entry)

        bucket.set_iam_policy(policy)

    async def sign_url_for_blob(
        self, bucket: ProviderBucket, key: str, expires_in_sec: int = 3600
    ) -> URL:
        if expires_in_sec > datetime.timedelta(days=7).total_seconds():
            raise ValueError("GCP do not support signed urls for more then 7 days")
        return URL(
            self._gcs_client.bucket(bucket.name)
            .blob(key)
            .generate_signed_url(expiration=datetime.timedelta(seconds=expires_in_sec))
        )


class GoogleBucketProvider(BucketProvider, GoogleUserBucketOperations):
    def __init__(
        self,
        gcs_client: GCSClient,
        iam_client: Any,
        iam_client_2: IAMCredentialsAsyncClient,
        sa_prefix: str = "bucket-api-",
    ):
        super().__init__(gcs_client)
        self._iam_client = iam_client
        self._iam_client_2 = iam_client_2
        self._sa_prefix = sa_prefix

    def _make_bucket_sa_name(self, bucket_name: str, *, write: bool) -> str:
        hasher = hashlib.new("sha256")
        hasher.update(bucket_name.encode("utf-8"))
        return (self._sa_prefix + ("wr-" if write else "rd-") + hasher.hexdigest())[:30]

    def _make_sa_email(self, name: str) -> str:
        return f"{name}@{self._gcs_client.project}.iam.gserviceaccount.com"

    def _make_bucket_sa_email(self, bucket_name: str, *, write: bool) -> str:
        return self._make_sa_email(self._make_bucket_sa_name(bucket_name, write=write))

    def _make_sa_full_name(self, name: str, *, placeholder: bool = False) -> str:
        return (
            f"projects/{'-' if placeholder else self._gcs_client.project}"
            f"/serviceAccounts/{self._make_sa_email(name)}"
        )

    def _make_bucket_sa_full_name(
        self, bucket_name: str, *, write: bool, placeholder: bool = False
    ) -> str:
        return self._make_sa_full_name(
            name=self._make_bucket_sa_name(bucket_name, write=write),
            placeholder=placeholder,
        )

    @run_in_executor
    def _create_bucket(self, bucket_name: str) -> None:
        self._gcs_client.create_bucket(bucket_name)

    @run_in_executor
    def _delete_bucket(self, bucket_name: str) -> None:
        self._gcs_client.bucket(bucket_name).delete()

    @run_in_executor
    def _add_iam_policy_to_bucket(
        self, bucket_name: str, role: str, sa_email: str
    ) -> None:
        bucket = self._gcs_client.bucket(bucket_name)
        policy = bucket.get_iam_policy()
        policy.bindings += [
            {"members": {policy.service_account(sa_email)}, "role": role}
        ]
        bucket.set_iam_policy(policy)

    @run_in_executor
    def _drop_sa_roles_for_buckets(self, sa_email: str) -> None:
        sa_member_entry = Policy.service_account(sa_email)
        for bucket in self._gcs_client.list_buckets():
            policy = bucket.get_iam_policy()
            changed = False
            for binding in policy.bindings:
                if sa_member_entry in binding["members"]:
                    changed = True
                    binding["members"].remove(sa_member_entry)
            if changed:
                bucket.set_iam_policy(policy)

    @run_in_executor
    def _create_sa(self, name: str, display_name: str, description: str) -> None:
        self._iam_client.projects().serviceAccounts().create(
            name="projects/" + self._gcs_client.project,
            body={
                "accountId": name,
                "serviceAccount": {
                    "displayName": display_name,
                    "description": description,
                },
            },
        ).execute()

    @run_in_executor
    def _delete_sa(self, full_name: str) -> None:
        self._iam_client.projects().serviceAccounts().delete(name=full_name).execute()

    @run_in_executor
    def _create_sa_key(self, full_name: str) -> Mapping[str, Any]:
        return (
            self._iam_client.projects()
            .serviceAccounts()
            .keys()
            .create(name=full_name)
            .execute()
        )

    async def create_bucket(self, name: str) -> ProviderBucket:
        write_role_created = False
        read_role_created = False
        bucket_created = False
        try:
            await self._create_bucket(name)
            bucket_created = True
            await self._create_sa(
                name=self._make_bucket_sa_name(name, write=True),
                display_name=f"RW SA for bucket {name}",
                description="Read/write SA generated by platform bucket api",
            )
            write_role_created = True
            await self._create_sa(
                name=self._make_bucket_sa_name(name, write=False),
                display_name=f"RO SA for bucket {name}",
                description="Read only SA generated by platform bucket api",
            )
            read_role_created = True
            await self._add_iam_policy_to_bucket(
                bucket_name=name,
                role="roles/storage.objectAdmin",
                sa_email=self._make_bucket_sa_email(name, write=True),
            )
            await self._add_iam_policy_to_bucket(
                bucket_name=name,
                role="roles/storage.objectViewer",
                sa_email=self._make_bucket_sa_email(name, write=False),
            )
        except Exception as e:
            if bucket_created:
                await self._delete_bucket(name)
            if write_role_created:
                await self._delete_sa(self._make_bucket_sa_full_name(name, write=True))
            if read_role_created:
                await self._delete_sa(self._make_bucket_sa_full_name(name, write=False))
            if isinstance(e, google.cloud.exceptions.Conflict):
                raise BucketExistsError(name)
            raise
        return ProviderBucket(name=name, provider_type=BucketsProviderType.GCP)

    async def delete_bucket(self, name: str) -> None:
        try:
            await self._delete_bucket(name)
            await self._delete_sa(self._make_bucket_sa_full_name(name, write=True))
            await self._delete_sa(self._make_bucket_sa_full_name(name, write=False))
        except google.cloud.exceptions.NotFound:
            raise BucketNotExistsError(name)

    async def get_bucket_credentials(
        self, bucket: ProviderBucket, write: bool, requester: str
    ) -> Mapping[str, str]:
        resp = await self._iam_client_2.generate_access_token(
            name=self._make_bucket_sa_full_name(
                bucket.name, write=write, placeholder=True
            ),
            scope=["https://www.googleapis.com/auth/cloud-platform"],
        )
        return {
            "project": self._gcs_client.project,
            "access_token": resp.access_token,
            "expire_time": resp.expire_time.isoformat(),
        }

    async def create_role(
        self, username: str, initial_permissions: Iterable[BucketPermission]
    ) -> ProviderRole:
        if len(username) > 30:
            raise ValueError("GCS account name cannot be larger then 30 characters")
        try:
            await self._create_sa(
                name=username,
                display_name="SA for bucket api persistent credentials",
                description="This service account was generated after user request",
            )
        except GoogleHttpError as e:
            if e.status_code == 409:
                raise RoleExistsError(username)
        resp = await self._create_sa_key(full_name=self._make_sa_full_name(username))
        role = ProviderRole(
            provider_type=BucketsProviderType.GCP,
            name=username,
            credentials={
                "project": self._gcs_client.project,
                "key_data": resp["privateKeyData"],
            },
        )
        await self._set_role_permissions(
            self._make_sa_email(role.name), initial_permissions
        )
        return role

    async def set_role_permissions(
        self, role: ProviderRole, permissions: Iterable[BucketPermission]
    ) -> None:
        sa_email = self._make_sa_email(role.name)
        await self._drop_sa_roles_for_buckets(sa_email)
        await self._set_role_permissions(sa_email, permissions)

    async def _set_role_permissions(
        self, sa_email: str, permissions: Iterable[BucketPermission]
    ) -> None:
        for permission in permissions:
            if permission.write:
                role = "roles/storage.objectAdmin"
            else:
                role = "roles/storage.objectViewer"
            await self._add_iam_policy_to_bucket(
                bucket_name=permission.bucket_name,
                role=role,
                sa_email=sa_email,
            )

    async def delete_role(self, role: ProviderRole) -> None:
        await self._delete_sa(self._make_sa_full_name(role.name))


@dataclass(frozen=True)
class OpenStackToken:
    token: str
    issued_at: datetime.datetime
    expires_at: datetime.datetime
    url: URL


@dataclass(frozen=True)
class OpenStackUser:
    name: str
    password: str
    read_only_containers: Sequence[str] = ()
    read_write_containers: Sequence[str] = ()


class OpenStackStorageApi:
    def __init__(self, account_id: str, password: str, url: URL):
        self._account_id = account_id
        self._password = password
        self._client = aiohttp.ClientSession()
        self._url = url
        self._token: Optional[OpenStackToken] = None

    async def __aenter__(self) -> "OpenStackStorageApi":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def close(self) -> None:
        await self._client.close()

    @property
    def account_id(self) -> str:
        return self._account_id

    async def _get_token(self) -> OpenStackToken:
        now = datetime.datetime.now(datetime.timezone.utc)
        if self._token is None or self._token.expires_at - now < datetime.timedelta(
            minutes=15
        ):
            self._token = await self.fetch_token()
        return self._token

    async def fetch_token(self) -> OpenStackToken:
        body = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self._account_id,
                            "password": self._password,
                        }
                    },
                }
            }
        }
        async with self._client.post(
            url=self._url / "v3/auth/tokens", json=body
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
            return OpenStackToken(
                token=resp.headers["x-subject-token"],
                expires_at=datetime.datetime.strptime(
                    data["token"]["expires_at"], "%Y-%m-%dT%H:%M:%S.%f%z"
                ),
                issued_at=datetime.datetime.strptime(
                    data["token"]["issued_at"], "%Y-%m-%dT%H:%M:%S.%f%z"
                ),
                url=URL(data["token"]["catalog"][0]["endpoints"][0]["url"]),
            )

    async def list_containers(self) -> List[str]:
        token = await self._get_token()
        headers = {"X-Auth-Token": token.token}
        async with self._client.get(url=token.url, headers=headers) as resp:
            resp.raise_for_status()
            return (await resp.text()).split("\n")

    async def create_container(
        self, container_name: str, meta: Optional[Mapping[str, str]] = None
    ) -> None:
        token = await self._get_token()
        headers = {"X-Auth-Token": token.token}
        headers.update(
            {f"X-Container-Meta-{key}": value for key, value in (meta or {}).items()}
        )
        async with self._client.put(
            url=token.url / container_name, headers=headers
        ) as resp:
            resp.raise_for_status()

    async def set_container_meta(
        self, container_name: str, meta: Optional[Mapping[str, str]] = None
    ) -> None:
        token = await self._get_token()
        headers = {"X-Auth-Token": token.token}
        headers.update(
            {f"X-Container-Meta-{key}": value for key, value in (meta or {}).items()}
        )
        async with self._client.put(
            url=token.url / container_name, headers=headers
        ) as resp:
            resp.raise_for_status()

    async def delete_container(self, container_name: str) -> None:
        token = await self._get_token()
        headers = {"X-Auth-Token": token.token}
        async with self._client.delete(
            url=token.url / container_name, headers=headers
        ) as resp:
            resp.raise_for_status()

    async def list_users(self) -> List[str]:
        token = await self._get_token()
        headers = {"X-Auth-Token": token.token}
        async with self._client.get(
            url=self._url / "v1/users", headers=headers
        ) as resp:
            resp.raise_for_status()
            return [
                info.strip().split(" ", 1)[0]
                for info in (await resp.text()).split("\n")
            ]

    async def update_or_create_user(self, user: OpenStackUser) -> OpenStackUser:
        token = await self._get_token()
        headers = {
            "X-Auth-Token": token.token,
            "X-Auth-Key": user.password,
            "X-User-Active": "on",
            "X-User-ACL-Containers-R": ",".join(user.read_only_containers),
            "X-User-ACL-Containers-W": ",".join(user.read_write_containers),
            "X-User-S3-Password": "yes",
        }
        async with self._client.put(
            url=self._url / "v1/users" / user.name, headers=headers
        ) as resp:
            resp.raise_for_status()
        return user

    async def delete_user(self, username: str) -> None:
        token = await self._get_token()
        headers = {
            "X-Auth-Token": token.token,
        }
        async with self._client.delete(
            url=self._url / "v1/users" / username, headers=headers
        ) as resp:
            resp.raise_for_status()


class OpenStackBucketProvider(BucketProvider):
    def __init__(self, api: OpenStackStorageApi, region_name: str, s3_url: str):
        self._api = api
        self._region_name = region_name
        self._s3_url = s3_url

    def _reader_name(self, container_name: str) -> str:
        return container_name + "-reader"

    def _writer_name(self, container_name: str) -> str:
        return container_name + "-writer"

    async def create_bucket(self, name: str) -> ProviderBucket:
        container_created = False
        reader_created = False
        reader = OpenStackUser(
            name=self._reader_name(name),
            password=secrets.token_hex(10),
            read_only_containers=[name],
        )
        writer = OpenStackUser(
            name=self._writer_name(name),
            password=secrets.token_hex(10),
            read_write_containers=[name],
        )
        try:
            await self._api.create_container(name)
            container_created = True
            await self._api.update_or_create_user(reader)
            reader_created = True
            await self._api.update_or_create_user(writer)
        except Exception:
            if reader_created:
                await self._api.delete_user(reader.name)
            if container_created:
                await self._api.delete_container(name)
        return ProviderBucket(
            name=name,
            provider_type=BucketsProviderType.OPEN_STACK,
            metadata={
                "reader": f"{reader.name}:{reader.password}",
                "writer": f"{writer.name}:{writer.password}",
            },
        )

    async def delete_bucket(self, name: str) -> None:
        try:
            await self._api.delete_user(self._reader_name(name))
        except ClientError:
            pass  # Can be already deleted
        try:
            await self._api.delete_user(self._writer_name(name))
        except ClientError:
            pass  # Can be already deleted
        await self._api.delete_container(name)

    async def get_bucket_credentials(
        self, bucket: ProviderBucket, write: bool, requester: str
    ) -> Mapping[str, str]:
        assert bucket.metadata
        if write:
            cred_str = bucket.metadata["writer"]
        else:
            cred_str = bucket.metadata["reader"]
        username, password = cred_str.rsplit(":", 1)
        return {
            "region_name": self._region_name,
            "endpoint_url": str(self._s3_url),
            "access_key_id": f"{self._api.account_id}_{username}",
            "secret_access_key": password,
        }

    async def create_role(
        self, username: str, initial_permissions: Iterable[BucketPermission]
    ) -> ProviderRole:
        password = secrets.token_hex(10)
        role = ProviderRole(
            name=username,
            provider_type=BucketsProviderType.OPEN_STACK,
            credentials={
                "region_name": self._region_name,
                "endpoint_url": str(self._s3_url),
                "access_key_id": f"{self._api.account_id}_{username}",
                "secret_access_key": password,
            },
        )
        # Set permissions also creates role
        await self.set_role_permissions(role, initial_permissions)
        return role

    async def set_role_permissions(
        self, role: ProviderRole, permissions: Iterable[BucketPermission]
    ) -> None:
        user = OpenStackUser(
            name=role.name,
            password=role.credentials["secret_access_key"],
            read_only_containers=[
                perm.bucket_name for perm in permissions if not perm.write
            ],
            read_write_containers=[
                perm.bucket_name for perm in permissions if perm.write
            ],
        )
        await self._api.update_or_create_user(user)

    async def delete_role(self, role: ProviderRole) -> None:
        await self._api.delete_user(role.name)

    async def set_public_access(self, bucket_name: str, public_access: bool) -> None:
        if public_access:
            meta = {"Type": "public"}
        else:
            meta = {"Type": "private"}
        await self._api.set_container_meta(bucket_name, meta)

    async def sign_url_for_blob(
        self, bucket: ProviderBucket, key: str, expires_in_sec: int = 3600
    ) -> URL:
        if expires_in_sec > datetime.timedelta(days=7).total_seconds():
            raise ValueError(
                "Open Stack do not support signed urls for more then 7 days"
            )
        session = aiobotocore.get_session()
        credentials = await self.get_bucket_credentials(
            bucket, write=False, requester="sign_url"
        )
        client_kwargs = dict(
            region_name=credentials["region_name"],
            endpoint_url=credentials["endpoint_url"],
            aws_secret_access_key=credentials["secret_access_key"],
            aws_access_key_id=credentials["access_key_id"],
        )
        async with session.create_client("s3", **client_kwargs) as s3_client:
            return URL(
                await s3_client.generate_presigned_url(
                    ClientMethod="get_object",
                    Params={"Bucket": bucket.name, "Key": key},
                    ExpiresIn=expires_in_sec,
                )
            )
