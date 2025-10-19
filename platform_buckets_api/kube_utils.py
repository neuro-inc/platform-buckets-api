import hashlib
import json
import logging
from typing import Any


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


ID_LABEL = "platform.apolo.us/id"
OWNER_LABEL = "platform.apolo.us/owner"
CREDENTIALS_NAME_LABEL = "platform.apolo.us/credentials_name"
BUCKET_NAME_LABEL = "platform.apolo.us/bucket_name"
APOLO_ORG_NAME_LABEL = "platform.apolo.us/org"
APOLO_PROJECT_NAME_LABEL = "platform.apolo.us/project"

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
            "org_name": payload["metadata"]["labels"].get(APOLO_ORG_NAME_LABEL),
            "project_name": payload["metadata"]["labels"].get(
                APOLO_PROJECT_NAME_LABEL, owner
            ),
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
        labels = {
            ID_LABEL: entry.id,
            OWNER_LABEL: entry.owner,
            APOLO_PROJECT_NAME_LABEL: entry.project_name,
            APOLO_ORG_NAME_LABEL: entry.org_name,
        }

        # Use this strange key as name to enable the uniqueness of owner/name pair
        if entry.name:
            labels[BUCKET_NAME_LABEL] = entry.name
            if entry.project_name == entry.owner:
                kwargs = {"name": entry.name, "owner": entry.owner}
            else:
                kwargs = {
                    "name": entry.name,
                    "project_name": entry.project_name,
                    "org_name": entry.org_name,
                }
        else:
            kwargs = {"id": entry.id}
        name = f"user-bucket-{_k8s_name_safe(**kwargs)}"

        spec = {
            "provider_type": entry.provider_bucket.provider_type.value,
            "provider_name": entry.provider_bucket.name,
            "created_at": datetime_dump(entry.created_at),
            "public": entry.public,
            "metadata": entry.provider_bucket.metadata,
        }

        if isinstance(entry, ImportedBucket):
            spec["imported"] = True
            spec["credentials"] = entry.credentials

        return {
            "kind": "UserBucket",
            "apiVersion": "neuromation.io/v1",
            "metadata": {
                "name": name,
                "labels": labels,
            },
            "spec": spec,
        }
