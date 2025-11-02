from collections.abc import AsyncIterator

from apolo_kube_client import (
    KubeClient,
    ResourceExists,
    ResourceNotFound,
    KubeClientSelector,
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
    OWNER_LABEL,
    CREDENTIALS_NAME_LABEL,
)


class K8SBucketsStorage(BucketsStorage):
    def __init__(self, kube_client_selector: KubeClientSelector) -> None:
        self._kube_client_selector = kube_client_selector

    async def create_bucket(self, bucket: BucketType) -> None:
        async with self._kube_client_selector.get_client(
            org_name=bucket.org_name, project_name=bucket.project_name
        ) as k8s:
            try:
                await k8s.neuromation_io_v1.user_bucket.create(
                    model=BucketCRDMapper.to_model(bucket)
                )
            except ResourceExists:
                raise ExistsError(
                    f"UserBucket for {bucket.owner} with name {bucket.name} already exists"
                )

    async def get_bucket(self, id_: str) -> BucketType:
        bucket_list = await self._kube_client_selector.host_client.neuromation_io_v1.user_bucket.get_list(
            label_selector=f"{ID_LABEL}={id_}", all_namespaces=True
        )

        if len(bucket_list.items) == 0:
            raise NotExistsError(f"UserBucket with id {id} doesn't exist")

        return BucketCRDMapper.from_model(bucket_list.items[0])

    async def get_bucket_by_name(
        self,
        name: str,
        org_name: str,  # type: ignore
        project_name: str,
    ) -> BucketType:
        label_selectors = [f"{BUCKET_NAME_LABEL}={name}"]

        async with self._kube_client_selector.get_client(
            org_name=org_name, project_name=project_name
        ) as k8s:
            bucket_list = await k8s.neuromation_io_v1.user_bucket.get_list(
                label_selector=",".join(label_selectors)
            )

            if len(bucket_list.items) == 0:
                raise NotExistsError(
                    f"UserBucket with org {org_name} project {project_name}, "
                    f"name {name} doesn't exist"
                )

            return BucketCRDMapper.from_model(bucket_list.items[0])

    @asyncgeneratorcontextmanager
    async def list_buckets(
        self, org_name: str, project_name: str
    ) -> AsyncIterator[BucketType]:
        async with self._kube_client_selector.get_client(
            org_name=org_name, project_name=project_name
        ) as k8s:
            user_bucket_list = await k8s.neuromation_io_v1.user_bucket.get_list()

            for user_bucket in user_bucket_list.items:
                yield BucketCRDMapper.from_model(user_bucket)

    async def delete_bucket(self, id: str) -> None:
        try:
            bucket = await self.get_bucket(id)
        except NotExistsError:
            return

        async with self._kube_client_selector.get_client(
            org_name=bucket.org_name, project_name=bucket.project_name
        ) as k8s:
            credentials_list = (
                await k8s.neuromation_io_v1.persistent_bucket_credential.get_list()
            )
            for credential in credentials_list.items:
                if id in credential.spec.bucket_ids:
                    raise StorageError(
                        "Cannot remove UserBucket that is mentioned "
                        f"in PersistentCredentials with id {credential.metadata.name}"
                    )
            name = BucketCRDMapper.to_model(bucket).metadata.name
            await k8s.neuromation_io_v1.user_bucket.delete(name=name)

    async def update_bucket(self, bucket: BucketType) -> None:
        async with self._kube_client_selector.get_client(
            org_name=bucket.org_name, project_name=bucket.project_name
        ) as k8s:
            name = BucketCRDMapper.to_model(bucket).metadata.name
            k8s_bucket = await k8s.neuromation_io_v1.user_bucket.get(name=name)
            update_model = BucketCRDMapper.to_model(bucket)
            update_model.metadata.resourceVersion = k8s_bucket.metadata.resourceVersion

            try:
                await k8s.neuromation_io_v1.user_bucket.update(model=update_model)  # type: ignore
            except ResourceNotFound:
                raise NotExistsError(f"UserBucket with id {bucket.id} doesn't exist")


class K8SCredentialsStorage(CredentialsStorage):
    def __init__(self, kube_client: KubeClient) -> None:
        self._kube_client = kube_client

    async def create_credentials(self, credentials: PersistentCredentials) -> None:
        try:
            await (
                self._kube_client.neuromation_io_v1.persistent_bucket_credential.create(
                    model=PersistentCredentialsCRDMapper.to_model(credentials),
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

        return PersistentCredentialsCRDMapper.from_model(pc_list.items[0])

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

        return PersistentCredentialsCRDMapper.from_model(pc_list.items[0])

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
            yield PersistentCredentialsCRDMapper.from_model(pc)

    async def delete_credentials(self, credentials: PersistentCredentials) -> None:
        try:
            credentials = await self.get_credentials(credentials.id)
        except ResourceNotFound:
            return

        name = PersistentCredentialsCRDMapper.to_model(credentials).metadata.name
        await self._kube_client.neuromation_io_v1.persistent_bucket_credential.delete(
            name=name, namespace=credentials.namespace
        )

    async def update_credentials(self, credentials: PersistentCredentials) -> None:
        name = PersistentCredentialsCRDMapper.to_model(credentials).metadata.name
        k8s_pc = (
            await self._kube_client.neuromation_io_v1.persistent_bucket_credential.get(
                name=name, namespace=credentials.namespace
            )
        )
        update_model = PersistentCredentialsCRDMapper.to_model(credentials)
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
