from collections.abc import AsyncIterator

from apolo_kube_client.apolo import create_namespace, generate_namespace_name
from apolo_kube_client import (
    KubeClient,
    ResourceExists,
    ResourceNotFound,
    V1UserBucketCRD,
    V1UserBucketCRDSpec,
    V1UserBucketCRDMetadata,
    V1PersistentBucketCredentialCRD,
    V1PersistentBucketCredentialCRDSpec,
    V1PersistentBucketCredentialCRDMetadata,
)

from platform_buckets_api.kube_utils import (
    BucketCRDMapper,
    PersistentCredentialsCRDMapper,
)
from platform_buckets_api.storage import (
    BucketsStorage,
    BucketType,
    CredentialsStorage,
    ExistsError,
    NotExistsError,
    PersistentCredentials,
    StorageError,
)
from platform_buckets_api.utils.asyncio import asyncgeneratorcontextmanager
from .kube_utils import (
    ID_LABEL,
    BUCKET_NAME_LABEL,
    APOLO_ORG_NAME_LABEL,
    APOLO_PROJECT_NAME_LABEL,
    OWNER_LABEL,
    CREDENTIALS_NAME_LABEL,
)


class K8SBucketsStorage(BucketsStorage):
    def __init__(self, kube_client: KubeClient) -> None:
        self._kube_client = kube_client

    def _bucket_to_k8s_model(self, bucket: BucketType) -> V1UserBucketCRD:
        bucket_crd_mapper = BucketCRDMapper.to_primitive(bucket)

        user_bucket_crd = V1UserBucketCRD(
            metadata=V1UserBucketCRDMetadata(
                name=bucket_crd_mapper.get("metadata", {}).get("name", ""),
                labels=bucket_crd_mapper.get("metadata", {}).get("labels", {}),
            ),
            spec=V1UserBucketCRDSpec(
                provider_type=bucket_crd_mapper.get("spec", {}).get(
                    "provider_type", None
                ),
                provider_name=bucket_crd_mapper.get("spec", {}).get(
                    "provider_name", None
                ),
                created_at=bucket_crd_mapper.get("spec", {}).get("created_at", None),
                public=bucket_crd_mapper.get("spec", {}).get("public", None),
                metadata=bucket_crd_mapper.get("spec", {}).get("metadata", None),
                imported=bucket_crd_mapper.get("spec", {}).get("imported", None),
                credentials=bucket_crd_mapper.get("spec", {}).get("credentials", None),
            ),
        )

        return user_bucket_crd

    async def create_bucket(self, bucket: BucketType) -> None:
        namespace = await create_namespace(
            kube_client=self._kube_client,
            org_name=bucket.org_name,
            project_name=bucket.project_name,
        )
        try:
            await self._kube_client.neuromation_io_v1.user_bucket.create(
                model=self._bucket_to_k8s_model(bucket),
                namespace=namespace.metadata.name,
            )
        except ResourceExists:
            raise ExistsError(
                f"UserBucket for {bucket.owner} with name {bucket.name} already exists"
            )

    async def get_bucket(self, id_: str) -> BucketType:
        bucket_list = await self._kube_client.neuromation_io_v1.user_bucket.get_list(
            label_selector=f"{ID_LABEL}={id_}", all_namespaces=True
        )

        if len(bucket_list.items) == 0:
            raise NotExistsError(f"UserBucket with id {id} doesn't exist")

        return BucketCRDMapper.from_primitive(bucket_list.items[0].model_dump())

    async def get_bucket_by_name(
        self, name: str, org_name: str | None, project_name: str
    ) -> BucketType:
        label_selectors = [f"{BUCKET_NAME_LABEL}={name}"]
        if project_name:
            label_selectors.append(f"{APOLO_PROJECT_NAME_LABEL}={project_name}")
        if org_name:
            label_selectors.append(f"{APOLO_ORG_NAME_LABEL}={org_name}")

        bucket_list = await self._kube_client.neuromation_io_v1.user_bucket.get_list(
            all_namespaces=True, label_selector=",".join(label_selectors)
        )

        if len(bucket_list.items) == 0:
            raise NotExistsError(
                f"UserBucket with org {org_name} project {project_name}, "
                f"name {name} doesn't exist"
            )

        return BucketCRDMapper.from_primitive(bucket_list.items[0].model_dump())

    @asyncgeneratorcontextmanager
    async def list_buckets(
        self, org_name: str | None = None, project_name: str | None = None
    ) -> AsyncIterator[BucketType]:
        label_selectors = []
        if project_name:
            label_selectors.append(f"{APOLO_PROJECT_NAME_LABEL}={project_name}")
        if org_name:
            label_selectors.append(f"{APOLO_ORG_NAME_LABEL}={org_name}")

        user_bucket_list = (
            await self._kube_client.neuromation_io_v1.user_bucket.get_list(
                all_namespaces=True, label_selector=",".join(label_selectors)
            )
        )

        for user_bucket in user_bucket_list.items:
            yield BucketCRDMapper.from_primitive(user_bucket.model_dump())

    async def delete_bucket(self, id: str) -> None:
        try:
            bucket = await self.get_bucket(id)
        except NotExistsError:
            return

        namespace = generate_namespace_name(
            org_name=bucket.org_name, project_name=bucket.project_name
        )
        credentials_list = await self._kube_client.neuromation_io_v1.persistent_bucket_credential.get_list(
            namespace=namespace,
        )
        for credential in credentials_list.items:
            if id in credential.spec.bucket_ids:
                raise StorageError(
                    "Cannot remove UserBucket that is mentioned "
                    f"in PersistentCredentials with id {credential.metadata.name}"
                )
        name = BucketCRDMapper.to_primitive(bucket)["metadata"]["name"]
        await self._kube_client.neuromation_io_v1.user_bucket.delete(
            name=name, namespace=bucket.namespace
        )

    async def update_bucket(self, bucket: BucketType) -> None:
        name = BucketCRDMapper.to_primitive(bucket)["metadata"]["name"]
        k8s_bucket = await self._kube_client.neuromation_io_v1.user_bucket.get(
            name=name, namespace=bucket.namespace
        )
        update_model = self._bucket_to_k8s_model(bucket)
        update_model.metadata.resourceVersion = k8s_bucket.metadata.resourceVersion

        try:
            await self._kube_client.neuromation_io_v1.user_bucket.update(
                model=update_model, namespace=bucket.namespace
            )
        except ResourceNotFound:
            raise NotExistsError(f"UserBucket with id {bucket.id} doesn't exist")


class K8SCredentialsStorage(CredentialsStorage):
    def __init__(self, kube_client: KubeClient) -> None:
        self._kube_client = kube_client

    def _ps_to_k8s_model(
        self, credentials: PersistentCredentials
    ) -> V1PersistentBucketCredentialCRD:
        ps_crd_mapper = PersistentCredentialsCRDMapper.to_primitive(credentials)

        pbc = V1PersistentBucketCredentialCRD(
            metadata=V1PersistentBucketCredentialCRDMetadata(
                name=ps_crd_mapper["metadata"]["name"],
                labels=ps_crd_mapper["metadata"]["labels"],
            ),
            spec=V1PersistentBucketCredentialCRDSpec(
                provider_name=ps_crd_mapper["spec"]["provider_name"],
                provider_type=ps_crd_mapper["spec"]["provider_type"],
                credentials=ps_crd_mapper["spec"]["credentials"],
                bucket_ids=ps_crd_mapper["spec"]["bucket_ids"],
                read_only=ps_crd_mapper["spec"]["read_only"],
            ),
        )
        return pbc

    async def create_credentials(self, credentials: PersistentCredentials) -> None:
        try:
            await (
                self._kube_client.neuromation_io_v1.persistent_bucket_credential.create(
                    model=self._ps_to_k8s_model(credentials),
                    namespace=credentials.namespace,
                )
            )
        except ResourceExists:
            raise ExistsError(
                f"PersistentCredentials for {credentials.owner} with "
                f"name {credentials.name} already exists"
            )

    async def get_credentials(self, id: str) -> PersistentCredentials:
        pc_list = await self._kube_client.neuromation_io_v1.persistent_bucket_credential.get_list(
            label_selector=f"{ID_LABEL}={id}", all_namespaces=True
        )

        if len(pc_list.items) == 0:
            raise NotExistsError(f"PersistentCredentials with id {id} doesn't exist")

        return PersistentCredentialsCRDMapper.from_primitive(
            pc_list.items[0].model_dump()
        )

    async def get_credentials_by_name(
        self,
        name: str,
        owner: str,
    ) -> PersistentCredentials:
        pc_list = await self._kube_client.neuromation_io_v1.persistent_bucket_credential.get_list(
            label_selector=f"{CREDENTIALS_NAME_LABEL}={name},{OWNER_LABEL}={owner}",
            all_namespaces=True,
        )

        if len(pc_list.items) == 0:
            raise NotExistsError(
                f"PersistentCredentials with name {name} and owner = {owner}"
                f" doesn't exist"
            )

        return PersistentCredentialsCRDMapper.from_primitive(
            pc_list.items[0].model_dump()
        )

    @asyncgeneratorcontextmanager
    async def list_credentials(
        self, owner: str | None = None
    ) -> AsyncIterator[PersistentCredentials]:
        label_selector = None
        if owner:
            label_selector = f"{OWNER_LABEL}={owner}"
        pc_list = await self._kube_client.neuromation_io_v1.persistent_bucket_credential.get_list(
            label_selector=label_selector,
            all_namespaces=True,
        )

        for pc in pc_list.items:
            yield PersistentCredentialsCRDMapper.from_primitive(pc.model_dump())

    async def delete_credentials(self, credentials: PersistentCredentials) -> None:
        try:
            credentials = await self.get_credentials(credentials.id)
        except ResourceNotFound:
            return

        name = PersistentCredentialsCRDMapper.to_primitive(credentials)["metadata"][
            "name"
        ]
        await self._kube_client.neuromation_io_v1.persistent_bucket_credential.delete(
            name=name, namespace=credentials.namespace
        )

    async def update_credentials(self, credentials: PersistentCredentials) -> None:
        name = PersistentCredentialsCRDMapper.to_primitive(credentials)["metadata"][
            "name"
        ]
        k8s_pc = (
            await self._kube_client.neuromation_io_v1.persistent_bucket_credential.get(
                name=name, namespace=credentials.namespace
            )
        )
        update_model = self._ps_to_k8s_model(credentials)
        update_model.metadata.resourceVersion = k8s_pc.metadata.resourceVersion

        try:
            await (
                self._kube_client.neuromation_io_v1.persistent_bucket_credential.update(
                    model=update_model,
                    namespace=credentials.namespace,
                )
            )
        except ResourceNotFound:
            raise NotExistsError(
                f"PersistentCredentials with id {credentials.id} doesn't exist"
            )
