import hashlib
import json
import logging


from .config import BucketsProviderType
from .storage import (
    BucketType,
    ImportedBucket,
    PersistentCredentials,
    ProviderBucket,
    ProviderRole,
    UserBucket,
)
from apolo_kube_client import (
    V1UserBucketCRD,
    V1PersistentBucketCredentialCRD,
    V1PersistentBucketCredentialCRDMetadata,
    V1PersistentBucketCredentialCRDSpec,
    V1UserBucketCRDMetadata,
    V1UserBucketCRDSpec,
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
    def from_model(model: V1PersistentBucketCredentialCRD) -> PersistentCredentials:
        return PersistentCredentials(
            id=model.metadata.labels[ID_LABEL],
            name=model.metadata.labels.get(CREDENTIALS_NAME_LABEL),
            owner=model.metadata.labels[OWNER_LABEL],
            role=ProviderRole(
                name=model.spec.provider_name,
                provider_type=BucketsProviderType(model.spec.provider_type),
                credentials=model.spec.credentials,
            ),
            bucket_ids=model.spec.bucket_ids,
            read_only=model.spec.read_only,
            namespace=model.metadata.namespace,
        )

    @staticmethod
    def to_model(entry: PersistentCredentials) -> V1PersistentBucketCredentialCRD:
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

        return V1PersistentBucketCredentialCRD(
            metadata=V1PersistentBucketCredentialCRDMetadata(
                name=name,
                labels=labels,
            ),
            spec=V1PersistentBucketCredentialCRDSpec(
                provider_name=entry.role.name,
                provider_type=entry.role.provider_type.value,
                credentials=entry.role.credentials,  # type: ignore
                bucket_ids=entry.bucket_ids,
                read_only=entry.read_only,
            ),
        )


class BucketCRDMapper:
    @staticmethod
    def from_model(model: V1UserBucketCRD) -> BucketType:
        owner = model.metadata.labels[OWNER_LABEL]
        common_kwargs = {
            "id": model.metadata.labels[ID_LABEL],
            "name": model.metadata.labels.get(BUCKET_NAME_LABEL),
            "owner": owner,
            "org_name": model.metadata.labels.get(APOLO_ORG_NAME_LABEL),
            "project_name": model.metadata.labels.get(APOLO_PROJECT_NAME_LABEL, owner),
            "created_at": datetime_load(model.spec.created_at),  # type: ignore
            "provider_bucket": ProviderBucket(
                provider_type=BucketsProviderType(model.spec.provider_type),
                name=model.spec.provider_name,  # type: ignore
                metadata=model.spec.metadata,
            ),
            "public": model.spec.public if model.spec.public is not None else False,
        }
        if model.spec.imported:
            return ImportedBucket(
                **common_kwargs,  # type: ignore
                credentials=model.spec.credentials,  # type: ignore
            )
        else:
            return UserBucket(
                **common_kwargs,  # type: ignore
            )

    @staticmethod
    def to_model(entry: BucketType) -> V1UserBucketCRD:
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

        return V1UserBucketCRD(
            metadata=V1UserBucketCRDMetadata(
                name=name,
                labels=labels,
            ),
            spec=V1UserBucketCRDSpec(**spec),  # type: ignore
        )
