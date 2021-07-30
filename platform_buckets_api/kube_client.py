import hashlib
import json
import logging
import ssl
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus, urlsplit

import aiohttp

from .config import BucketsProviderType, KubeClientAuthType
from .storage import ProviderBucket, ProviderRole, UserBucket, UserCredentials


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


OWNER_LABEL = "platform.neuromation.io/owner"


def _k8s_name_safe(**kwargs: str) -> str:
    hasher = hashlib.new("sha256")
    data = json.dumps(kwargs, sort_keys=True)
    hasher.update(data.encode("utf-8"))
    return hasher.hexdigest()


class UserCredentialsCRDMapper:
    @staticmethod
    def from_primitive(payload: Dict[str, Any]) -> UserCredentials:
        return UserCredentials(
            owner=payload["metadata"]["labels"][OWNER_LABEL],
            role=ProviderRole(
                id=payload["spec"]["provider_id"],
                provider_type=BucketsProviderType(payload["spec"]["provider_type"]),
                credentials=payload["spec"]["credentials"],
            ),
        )

    @staticmethod
    def to_primitive(entry: UserCredentials) -> Dict[str, Any]:
        return {
            "kind": "UserBucketCredential",
            "apiVersion": "neuromation.io/v1",
            "metadata": {
                "name": f"user-credentials--{_k8s_name_safe(owner=entry.owner)}",
                "labels": {
                    OWNER_LABEL: entry.owner,
                },
            },
            "spec": {
                "provider_id": entry.role.id,
                "provider_type": entry.role.provider_type.value,
                "credentials": entry.role.credentials,
            },
        }


class UserBucketCRDMapper:
    @staticmethod
    def from_primitive(payload: Dict[str, Any]) -> UserBucket:
        return UserBucket(
            name=payload["spec"]["name"],
            owner=payload["metadata"]["labels"][OWNER_LABEL],
            provider_bucket=ProviderBucket(
                id=payload["spec"]["provider_id"],
                provider_type=BucketsProviderType(payload["spec"]["provider_type"]),
                name=payload["spec"]["provider_name"],
            ),
        )

    @staticmethod
    def to_primitive(entry: UserBucket) -> Dict[str, Any]:
        name = f"user-bucket-{_k8s_name_safe(owner=entry.owner, nmae=entry.name)}"
        return {
            "kind": "UserBucket",
            "apiVersion": "neuromation.io/v1",
            "metadata": {
                "name": name,
                "labels": {
                    OWNER_LABEL: entry.owner,
                },
            },
            "spec": {
                "name": entry.name,
                "provider_id": entry.provider_bucket.id,
                "provider_type": entry.provider_bucket.provider_type.value,
                "provider_name": entry.provider_bucket.name,
            },
        }


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
    def _user_bucket_credentials_url(self) -> str:
        return (
            f"{self._base_url}/apis/neuromation.io/v1/"
            f"namespaces/{self._namespace}/userbucketcredentials"
        )

    def _generate_user_bucket_credential_url(self, name: str) -> str:
        return f"{self._user_bucket_credentials_url}/{name}"

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

    async def create_user_bucket_credential(
        self, user_credentials: UserCredentials
    ) -> None:
        url = self._user_bucket_credentials_url
        payload = await self._request(
            method="POST",
            url=url,
            json=UserCredentialsCRDMapper.to_primitive(user_credentials),
        )
        self._raise_for_status(payload)

    async def list_user_bucket_credentials(
        self, owner: Optional[str] = None
    ) -> List[UserCredentials]:
        url = self._user_bucket_credentials_url
        params = []
        if owner:
            params = [("labelSelector", f"{OWNER_LABEL}={owner}")]
        payload = await self._request(method="GET", url=url, params=params)
        return [
            UserCredentialsCRDMapper.from_primitive(item)
            for item in payload.get("items", [])
        ]

    async def get_user_bucket_credential(self, name: str) -> UserCredentials:
        url = self._generate_user_bucket_credential_url(name)
        payload = await self._request(method="GET", url=url)
        self._raise_for_status(payload)
        return UserCredentialsCRDMapper.from_primitive(payload)

    async def remove_user_bucket_credential(
        self, user_credentials: UserCredentials
    ) -> None:
        name = UserCredentialsCRDMapper.to_primitive(user_credentials)["metadata"][
            "name"
        ]
        url = self._generate_user_bucket_credential_url(name)
        payload = await self._request(method="DELETE", url=url)
        self._raise_for_status(payload)

    async def create_user_bucket(self, user_bucket: UserBucket) -> None:
        url = self._user_buckets_url
        payload = await self._request(
            method="POST", url=url, json=UserBucketCRDMapper.to_primitive(user_bucket)
        )
        self._raise_for_status(payload)

    async def list_user_buckets(self, owner: Optional[str] = None) -> List[UserBucket]:
        url = self._user_buckets_url
        params = []
        if owner:
            params = [("labelSelector", quote_plus(f"{OWNER_LABEL}={owner}"))]
        payload = await self._request(method="GET", url=url, params=params)
        return [
            UserBucketCRDMapper.from_primitive(item)
            for item in payload.get("items", [])
        ]

    async def get_user_bucket(self, name: str) -> UserBucket:
        url = self._generate_user_bucket_url(name)
        payload = await self._request(method="GET", url=url)
        self._raise_for_status(payload)
        return UserBucketCRDMapper.from_primitive(payload)

    async def remove_user_bucket(self, bucket: UserBucket) -> None:
        name = UserBucketCRDMapper.to_primitive(bucket)["metadata"]["name"]
        url = self._generate_user_bucket_url(name)
        payload = await self._request(method="DELETE", url=url)
        self._raise_for_status(payload)
