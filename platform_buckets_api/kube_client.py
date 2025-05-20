import hashlib
import json
import logging
from typing import Any

from apolo_kube_client.apolo import normalize_name
from apolo_kube_client.client import KubeClient

from .config import BucketsProviderType
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


ID_LABEL = "platform.neuromation.io/id"
OWNER_LABEL = "platform.neuromation.io/owner"
CREDENTIALS_NAME_LABEL = "platform.neuromation.io/credentials_name"
BUCKET_NAME_LABEL = "platform.neuromation.io/bucket_name"
ORG_NAME_LABEL = "platform.neuromation.io/org_name"
PROJECT_LABEL = "platform.neuromation.io/project"

NO_ORG = "NO_ORG"


def _k8s_name_safe(**kwargs: str) -> str:
    hasher = hashlib.new("sha256")
    data = json.dumps(kwargs, sort_keys=True)
    hasher.update(data.encode("utf-8"))
    return hasher.hexdigest()


class PersistentCredentialsCRDMapper:
    @staticmethod
    def from_primitive(payload: dict[str, Any]) -> PersistentCredentials:
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
            namespace=payload["metadata"]["namespace"],
        )

    @staticmethod
    def to_primitive(entry: PersistentCredentials) -> dict[str, Any]:
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
    def from_primitive(payload: dict[str, Any]) -> BucketType:
        owner = payload["metadata"]["labels"][OWNER_LABEL]
        common_kwargs = {
            "id": payload["metadata"]["labels"][ID_LABEL],
            "name": payload["metadata"]["labels"].get(BUCKET_NAME_LABEL),
            "owner": owner,
            "org_name": payload["metadata"]["labels"].get(ORG_NAME_LABEL),
            "project_name": payload["metadata"]["labels"].get(PROJECT_LABEL, owner),
            "created_at": datetime_load(payload["spec"]["created_at"]),
            "provider_bucket": ProviderBucket(
                provider_type=BucketsProviderType(payload["spec"]["provider_type"]),
                name=payload["spec"]["provider_name"],
                metadata=payload["spec"].get("metadata"),
            ),
            "public": payload["spec"].get("public", False),
        }
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
    def to_primitive(entry: BucketType) -> dict[str, Any]:
        # Use this strange key as name to enable uniqueness of owner/name pair
        if entry.name:
            if entry.project_name == entry.owner:
                kwargs = {"name": entry.name, "owner": entry.owner}
            else:
                kwargs = {"name": entry.name, "project_name": entry.project_name}
                if entry.org_name:
                    kwargs["org_name"] = entry.org_name
        else:
            kwargs = {"id": entry.id}
        name = f"user-bucket-{_k8s_name_safe(**kwargs)}"
        labels = {
            ID_LABEL: entry.id,
            OWNER_LABEL: entry.owner,
        }
        if entry.name:
            labels[BUCKET_NAME_LABEL] = entry.name
        if entry.org_name:
            labels[ORG_NAME_LABEL] = entry.org_name
        if entry.project_name != entry.owner:
            labels[PROJECT_LABEL] = entry.project_name
        res: dict[str, Any] = {
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


class KubeApi:
    """
    Kube methods used by a volume resolver
    """

    def __init__(self, kube_client: KubeClient):
        self._kube = kube_client

    @property
    def _apis_url(self) -> str:
        return f"{self._kube._base_url}/apis"

    @property
    def _neuromation_url(self) -> str:
        return f"{self._apis_url}/neuromation.io/v1"

    @property
    def _persistent_bucket_credentials_url(self) -> str:
        return f"{self._neuromation_url}/persistentbucketcredentials"

    def _generate_persistent_bucket_credential_url(
        self,
        namespace: str | None,
        name: str | None = None,
    ) -> str:
        if not namespace:
            url = self._persistent_bucket_credentials_url
        else:
            url = (
                f"{self._neuromation_url}/namespaces/{namespace}"
                f"/persistentbucketcredentials"
            )
        if name:
            url = f"{url}/{name}"
        return url

    def _generate_user_buckets_url(
        self, namespace: str, name: str | None = None
    ) -> str:
        url = f"{self._neuromation_url}/namespaces/{namespace}/userbuckets"
        if name:
            url = f"{url}/{name}"
        return url

    @property
    def _user_buckets_url(self) -> str:
        return f"{self._kube._base_url}/apis/neuromation.io/v1/userbuckets"

    async def create_persistent_credentials(
        self,
        user_credentials: PersistentCredentials,
    ) -> None:
        url = self._generate_persistent_bucket_credential_url(
            user_credentials.namespace
        )
        await self._kube.post(
            url=url,
            json=PersistentCredentialsCRDMapper.to_primitive(user_credentials),
        )

    async def list_persistent_credentials(
        self,
        id: str | None = None,
        owner: str | None = None,
        name: str | None = None,
    ) -> list[PersistentCredentials]:
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
        payload = await self._kube.get(url=url, params=params)
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
        url = self._generate_persistent_bucket_credential_url(
            user_credentials.namespace, name
        )
        await self._kube.delete(url=url)

    async def update_persistent_credentials(
        self,
        user_credentials: PersistentCredentials,
    ) -> None:
        data = PersistentCredentialsCRDMapper.to_primitive(user_credentials)
        name = data["metadata"]["name"]
        url = self._generate_persistent_bucket_credential_url(
            user_credentials.namespace, name
        )
        payload = await self._kube.get(url=url)
        data["metadata"]["resourceVersion"] = payload["metadata"]["resourceVersion"]
        await self._kube.put(url=url, json=data)

    async def create_user_bucket(self, user_bucket: BucketType) -> None:
        url = self._generate_user_buckets_url(namespace=user_bucket.namespace)
        await self._kube.post(url=url, json=BucketCRDMapper.to_primitive(user_bucket))

    async def list_user_buckets(
        self,
        id: str | None = None,
        owner: str | None = None,
        name: str | None = None,
        org_name: str | None = None,
        project_name: str | None = None,
    ) -> list[BucketType]:
        url = self._user_buckets_url
        label_selectors = []
        params = []
        if id:
            label_selectors.append(f"{ID_LABEL}={id}")
        if owner:
            label_selectors.append(f"{OWNER_LABEL}={owner}")
        if name:
            label_selectors.append(f"{BUCKET_NAME_LABEL}={name}")
        if org_name:
            normalized_name = normalize_name(org_name)
            if normalized_name != normalize_name(NO_ORG):
                normalized_name = org_name
            label_selectors.append(f"{ORG_NAME_LABEL}={normalized_name}")
        if label_selectors:
            params += [("labelSelector", ",".join(label_selectors))]
        payload = await self._kube.get(url=url, params=params)
        buckets = []
        for item in payload.get("items", []):
            bucket = BucketCRDMapper.from_primitive(item)
            if project_name and project_name != bucket.project_name:
                continue
            buckets.append(bucket)
        return buckets

    async def remove_user_bucket(self, bucket: BucketType) -> None:
        name = BucketCRDMapper.to_primitive(bucket)["metadata"]["name"]
        url = self._generate_user_buckets_url(bucket.namespace, name)
        await self._kube.delete(url=url)

    async def update_user_bucket(self, bucket: BucketType) -> None:
        data = BucketCRDMapper.to_primitive(bucket)
        name = data["metadata"]["name"]
        url = self._generate_user_buckets_url(bucket.namespace, name)
        payload = await self._kube.get(url=url)
        data["metadata"]["resourceVersion"] = payload["metadata"]["resourceVersion"]
        await self._kube.put(url=url, json=data)
