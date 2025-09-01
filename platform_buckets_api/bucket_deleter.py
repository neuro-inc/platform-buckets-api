import logging
from typing import Self

from apolo_events_client import (
    EventsClientConfig,
    EventType,
    RecvEvent,
    StreamType,
    from_config,
)

from .service import BucketsService, PersistentCredentialsService
from .storage import BucketType

logger = logging.getLogger(__name__)


class BucketDeleter:
    ADMIN_STREAM = StreamType("platform-admin")
    PROJECT_REMOVE = EventType("project-remove")

    def __init__(
        self,
        config: EventsClientConfig | None,
        buckets_service: BucketsService,
        credentials_service: PersistentCredentialsService,
    ) -> None:
        self._buckets_service = buckets_service
        self._credentials_service = credentials_service
        self._client = from_config(config)

    async def __aenter__(self) -> Self:
        await self._client.__aenter__()
        await self._client.subscribe_group(self.ADMIN_STREAM, self._on_admin_event)
        return self

    async def __aexit__(self, exc_typ: object, exc_val: object, exc_tb: object) -> None:
        await self._client.aclose()

    async def _on_admin_event(self, ev: RecvEvent) -> None:
        if ev.event_type != self.PROJECT_REMOVE:
            return

        try:
            await self._process_project_deletion(ev)
        except Exception:
            logger.exception("Error in _on_admin_event")

        await self._client.ack({self.ADMIN_STREAM: [ev.tag]})

    async def _process_project_deletion(self, ev: RecvEvent) -> None:
        cluster = ev.cluster
        assert cluster is not None
        org = ev.org
        assert org is not None
        project = ev.project
        assert project is not None

        logger.info(
            "Processing bucket cleanup for deleted project: cluster=%s, org=%s, project=%s",
            cluster,
            org,
            project,
        )

        buckets_to_delete: list[BucketType] = []
        # Use storage directly to bypass permission checks for system cleanup
        async with self._buckets_service._storage.list_buckets(
            org_name=org, project_name=project
        ) as bucket_iterator:
            async for bucket in bucket_iterator:
                buckets_to_delete.append(bucket)

        logger.info(
            "Found %d buckets to delete for project %s/%s in cluster %s",
            len(buckets_to_delete),
            org,
            project,
            cluster,
        )

        for bucket in buckets_to_delete:
            try:
                await self._delete_bucket_and_credentials(bucket)
                logger.info(
                    "Successfully deleted bucket %s (id=%s) and its credentials",
                    bucket.name,
                    bucket.id,
                )
            except Exception:
                logger.exception(
                    "Cannot delete bucket %s (id=%s) for project %s/%s in cluster %s",
                    bucket.name,
                    bucket.id,
                    org,
                    project,
                    cluster,
                )

    async def _delete_bucket_and_credentials(self, bucket: BucketType) -> None:
        async with self._credentials_service.list_credentials_with_bucket(
            bucket.id
        ) as credential_iterator:
            async for credential in credential_iterator:
                try:
                    if len(credential.bucket_ids) == 1:
                        await self._credentials_service.delete_credentials(credential)
                        logger.debug(
                            "Deleted credential %s (id=%s) that only referenced bucket %s",
                            credential.name,
                            credential.id,
                            bucket.name,
                        )
                    else:
                        updated_bucket_ids = [
                            bid for bid in credential.bucket_ids if bid != bucket.id
                        ]
                        await self._credentials_service.update_credentials(
                            credential,
                            bucket_ids=updated_bucket_ids,
                            read_only=credential.read_only,
                        )
                        logger.debug(
                            "Updated credential %s (id=%s) to remove bucket %s reference",
                            credential.name,
                            credential.id,
                            bucket.name,
                        )
                except Exception:
                    logger.exception(
                        "Failed to update/delete credential %s (id=%s) for bucket %s",
                        credential.name,
                        credential.id,
                        bucket.name,
                    )

        await self._buckets_service.delete_bucket(bucket.id)
