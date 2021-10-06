import hashlib
import json
import logging
import ssl
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit

import aiohttp

from .config import BucketsProviderType, KubeClientAuthType
from .storage import (
    BucketType,
    ImportedBucket,
    PersistentCredentials,
    ProviderBucket,
    ProviderRole,
    UserBucket,
)
from .utils import datetime_dump, datetime_load


logger = logging.getLogger(__name__)


class KubeClientException(Exception):
    pass


class ResourceNotFound(KubeClientException):
    pass


class ResourceInvalid(KubeClientException):
    pass


class ResourceExists(KubeClientException):
    pass


class ResourceBadRequest(KubeClientException):
    pass


class ResourceGone(KubeClientException):
    pass


ID_LABEL = "platform.neuromation.io/id"
OWNER_LABEL = "platform.neuromation.io/owner"
CREDENTIALS_NAME_LABEL = "platform.neuromation.io/credentials_name"
BUCKET_NAME_LABEL = "platform.neuromation.io/bucket_name"


def _k8s_name_safe(**kwargs: str) -> str:
    hasher = hashlib.new("sha256")
    data = json.dumps(kwargs, sort_keys=True)
    hasher.update(data.encode("utf-8"))
    return hasher.hexdigest()


class PersistentCredentialsCRDMapper:
    @staticmethod
    def from_primitive(payload: Dict[str, Any]) -> PersistentCredentials:
        return PersistentCredentials(
            id=payload["metadata"]["labels"][ID_LABEL],
            name=payload["metadata"]["labels"].get(CREDENTIALS_NAME_LABEL),
            owner=payload["metadata"]["labels"][OWNER_LABEL],
            role=ProviderRole(
                name=payload["spec"]["provider_name"],
                provider_type=BucketsProviderType(payload["spec"]["provider_type"]),
                credentials=payload["spec"]["credentials"],
            ),
            bucket_ids=payload["spec"]["bucket_ids"],
            read_only=payload["spec"].get("read_only", False),
        )

    @staticmethod
    def to_primitive(entry: PersistentCredentials) -> Dict[str, Any]:
        if entry.name:
            name = (
                "persistent-bucket-credentials-"
                f"{_k8s_name_safe(owner=entry.owner, name=entry.name)}"
            )
        else:
            name = f"persistent-bucket-credentials-{_k8s_name_safe(id=entry.id)}"
        labels = {
            ID_LABEL: entry.id,
            OWNER_LABEL: entry.owner,
        }
        if entry.name:
            labels[CREDENTIALS_NAME_LABEL] = entry.name
        return {
            "kind": "PersistentBucketCredential",
            "apiVersion": "neuromation.io/v1",
            "metadata": {
                "name": name,
                "labels": labels,
            },
            "spec": {
                "provider_name": entry.role.name,
                "provider_type": entry.role.provider_type.value,
                "credentials": entry.role.credentials,
                "bucket_ids": entry.bucket_ids,
                "read_only": entry.read_only,
            },
        }


class BucketCRDMapper:
    @staticmethod
    def from_primitive(payload: Dict[str, Any]) -> BucketType:
        common_kwargs = dict(
            id=payload["metadata"]["labels"][ID_LABEL],
            name=payload["metadata"]["labels"].get(BUCKET_NAME_LABEL),
            owner=payload["metadata"]["labels"][OWNER_LABEL],
            created_at=datetime_load(payload["spec"]["created_at"]),
            provider_bucket=ProviderBucket(
                provider_type=BucketsProviderType(payload["spec"]["provider_type"]),
                name=payload["spec"]["provider_name"],
                metadata=payload["spec"].get("metadata"),
            ),
            public=payload["spec"].get("public", False),
        )
        if payload["spec"].get("imported", False):
            return ImportedBucket(
                **common_kwargs,
                credentials=payload["spec"]["credentials"],
            )
        else:
            return UserBucket(
                **common_kwargs,
            )

    @staticmethod
    def to_primitive(entry: BucketType) -> Dict[str, Any]:
        # Use this strange key as name to enable uniqueness of owner/name pair
        if entry.name:
            name = f"user-bucket-{_k8s_name_safe(owner=entry.owner, name=entry.name)}"
        else:
            name = f"user-bucket-{_k8s_name_safe(id=entry.id)}"
        labels = {
            ID_LABEL: entry.id,
            OWNER_LABEL: entry.owner,
        }
        if entry.name:
            labels[BUCKET_NAME_LABEL] = entry.name
        res: Dict[str, Any] = {
            "kind": "UserBucket",
            "apiVersion": "neuromation.io/v1",
            "metadata": {
                "name": name,
                "labels": labels,
            },
            "spec": {
                "provider_type": entry.provider_bucket.provider_type.value,
                "provider_name": entry.provider_bucket.name,
                "created_at": datetime_dump(entry.created_at),
                "public": entry.public,
                "metadata": entry.provider_bucket.metadata,
            },
        }
        if isinstance(entry, ImportedBucket):
            res["spec"]["imported"] = True
            res["spec"]["credentials"] = entry.credentials
        return res


class KubeClient:
    def __init__(
        self,
        *,
        base_url: str,
        namespace: str,
        cert_authority_path: Optional[str] = None,
        cert_authority_data_pem: Optional[str] = None,
        auth_type: KubeClientAuthType = KubeClientAuthType.CERTIFICATE,
        auth_cert_path: Optional[str] = None,
        auth_cert_key_path: Optional[str] = None,
        token: Optional[str] = None,
        token_path: Optional[str] = None,
        conn_timeout_s: int = 300,
        read_timeout_s: int = 100,
        watch_timeout_s: int = 1800,
        conn_pool_size: int = 100,
        trace_configs: Optional[List[aiohttp.TraceConfig]] = None,
    ) -> None:
        self._base_url = base_url
        self._namespace = namespace

        self._cert_authority_data_pem = cert_authority_data_pem
        self._cert_authority_path = cert_authority_path

        self._auth_type = auth_type
        self._auth_cert_path = auth_cert_path
        self._auth_cert_key_path = auth_cert_key_path
        self._token = token
        self._token_path = token_path

        self._conn_timeout_s = conn_timeout_s
        self._read_timeout_s = read_timeout_s
        self._watch_timeout_s = watch_timeout_s
        self._conn_pool_size = conn_pool_size
        self._trace_configs = trace_configs

        self._client: Optional[aiohttp.ClientSession] = None

    @property
    def _is_ssl(self) -> bool:
        return urlsplit(self._base_url).scheme == "https"

    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        if not self._is_ssl:
            return None
        ssl_context = ssl.create_default_context(
            cafile=self._cert_authority_path, cadata=self._cert_authority_data_pem
        )
        if self._auth_type == KubeClientAuthType.CERTIFICATE:
            ssl_context.load_cert_chain(
                self._auth_cert_path,  # type: ignore
                self._auth_cert_key_path,
            )
        return ssl_context

    async def init(self) -> None:
        self._client = await self.create_http_client()

    async def create_http_client(self) -> aiohttp.ClientSession:
        connector = aiohttp.TCPConnector(
            limit=self._conn_pool_size, ssl=self._create_ssl_context()
        )
        if self._auth_type == KubeClientAuthType.TOKEN:
            token = self._token
            if not token:
                assert self._token_path is not None
                token = Path(self._token_path).read_text()
            headers = {"Authorization": "Bearer " + token}
        else:
            headers = {}
        timeout = aiohttp.ClientTimeout(
            connect=self._conn_timeout_s, total=self._read_timeout_s
        )
        return aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
            trace_configs=self._trace_configs,
        )

    @property
    def namespace(self) -> str:
        return self._namespace

    async def close(self) -> None:
        if self._client:
            await self._client.close()
            self._client = None

    async def __aenter__(self) -> "KubeClient":
        await self.init()
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    @property
    def _api_v1_url(self) -> str:
        return f"{self._base_url}/api/v1"

    def _generate_namespace_url(self, namespace_name: Optional[str] = None) -> str:
        namespace_name = namespace_name or self._namespace
        return f"{self._api_v1_url}/namespaces/{namespace_name}"

    @property
    def _namespace_url(self) -> str:
        return self._generate_namespace_url(self._namespace)

    @property
    def _persistent_bucket_credentials_url(self) -> str:
        return (
            f"{self._base_url}/apis/neuromation.io/v1/"
            f"namespaces/{self._namespace}/persistentbucketcredentials"
        )

    def _generate_persistent_bucket_credential_url(self, name: str) -> str:
        return f"{self._persistent_bucket_credentials_url}/{name}"

    @property
    def _user_buckets_url(self) -> str:
        return (
            f"{self._base_url}/apis/neuromation.io/v1/"
            f"namespaces/{self._namespace}/userbuckets"
        )

    def _generate_user_bucket_url(self, name: str) -> str:
        return f"{self._user_buckets_url}/{name}"

    async def _request(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        assert self._client, "client is not initialized"
        async with self._client.request(*args, **kwargs) as response:
            # TODO (A Danshyn 05/21/18): check status code etc
            payload = await response.json()
            return payload

    def _raise_for_status(self, payload: Dict[str, Any]) -> None:
        kind = payload["kind"]
        if kind == "Status":
            if payload.get("status") == "Success":
                return
            code = payload.get("code")
            if code == 400:
                raise ResourceBadRequest(payload)
            if code == 404:
                raise ResourceNotFound(payload)
            if code == 409:
                raise ResourceExists(payload)
            if code == 410:
                raise ResourceGone(payload)
            if code == 422:
                raise ResourceInvalid(payload["message"])
            raise KubeClientException(payload["message"])

    async def create_persistent_credentials(
        self, user_credentials: PersistentCredentials
    ) -> None:
        url = self._persistent_bucket_credentials_url
        payload = await self._request(
            method="POST",
            url=url,
            json=PersistentCredentialsCRDMapper.to_primitive(user_credentials),
        )
        self._raise_for_status(payload)

    async def list_persistent_credentials(
        self,
        id: Optional[str] = None,
        owner: Optional[str] = None,
        name: Optional[str] = None,
    ) -> List[PersistentCredentials]:
        url = self._persistent_bucket_credentials_url
        label_selectors = []
        params = []
        if id:
            label_selectors.append(f"{ID_LABEL}={id}")
        if owner:
            label_selectors.append(f"{OWNER_LABEL}={owner}")
        if name:
            label_selectors.append(f"{CREDENTIALS_NAME_LABEL}={name}")
        if label_selectors:
            params += [("labelSelector", ",".join(label_selectors))]
        payload = await self._request(method="GET", url=url, params=params)
        return [
            PersistentCredentialsCRDMapper.from_primitive(item)
            for item in payload.get("items", [])
        ]

    async def remove_persistent_credentials(
        self, user_credentials: PersistentCredentials
    ) -> None:
        name = PersistentCredentialsCRDMapper.to_primitive(user_credentials)[
            "metadata"
        ]["name"]
        url = self._generate_persistent_bucket_credential_url(name)
        payload = await self._request(method="DELETE", url=url)
        self._raise_for_status(payload)

    async def create_user_bucket(self, user_bucket: BucketType) -> None:
        url = self._user_buckets_url
        payload = await self._request(
            method="POST", url=url, json=BucketCRDMapper.to_primitive(user_bucket)
        )
        self._raise_for_status(payload)

    async def list_user_buckets(
        self,
        id: Optional[str] = None,
        owner: Optional[str] = None,
        name: Optional[str] = None,
    ) -> List[BucketType]:
        url = self._user_buckets_url
        label_selectors = []
        params = []
        if id:
            label_selectors.append(f"{ID_LABEL}={id}")
        if owner:
            label_selectors.append(f"{OWNER_LABEL}={owner}")
        if name:
            label_selectors.append(f"{BUCKET_NAME_LABEL}={name}")
        if label_selectors:
            params += [("labelSelector", ",".join(label_selectors))]
        payload = await self._request(method="GET", url=url, params=params)
        return [
            BucketCRDMapper.from_primitive(item) for item in payload.get("items", [])
        ]

    async def get_user_bucket(self, name: str) -> BucketType:
        url = self._generate_user_bucket_url(name)
        payload = await self._request(method="GET", url=url)
        self._raise_for_status(payload)
        return BucketCRDMapper.from_primitive(payload)

    async def remove_user_bucket(self, bucket: BucketType) -> None:
        name = BucketCRDMapper.to_primitive(bucket)["metadata"]["name"]
        url = self._generate_user_bucket_url(name)
        payload = await self._request(method="DELETE", url=url)
        self._raise_for_status(payload)

    async def update_user_bucket(self, bucket: BucketType) -> None:
        data = BucketCRDMapper.to_primitive(bucket)
        name = data["metadata"]["name"]
        url = self._generate_user_bucket_url(name)
        payload = await self._request(method="GET", url=url)
        self._raise_for_status(payload)
        data["metadata"]["resourceVersion"] = payload["metadata"]["resourceVersion"]
        payload = await self._request(method="PUT", url=url, json=data)
        self._raise_for_status(payload)
