from __future__ import annotations

from collections.abc import AsyncIterator
import asyncio
import uuid
from datetime import UTC, datetime

import pytest
from apolo_events_client import EventType, RecvEvent, RecvEvents, StreamType, Tag
from apolo_events_client.pytest import EventsQueues

from platform_buckets_api.bucket_deleter import BucketDeleter
from platform_buckets_api.service import BucketsService, PersistentCredentialsService


@pytest.fixture
async def bucket_deleter(
    events_config,
    buckets_service: BucketsService,
    credentials_service: PersistentCredentialsService,
) -> AsyncIterator[BucketDeleter]:
    deleter = BucketDeleter(
        config=events_config,
        buckets_service=buckets_service,
        credentials_service=credentials_service,
    )
    async with deleter:
        yield deleter


async def test_bucket_deleter_processes_project_remove_event(
    events_queues: EventsQueues,
    bucket_deleter: BucketDeleter,
    buckets_service: BucketsService,
    credentials_service: PersistentCredentialsService,
) -> None:
    cluster = "test-cluster"
    org = "test-org"
    project = "test-project"

    # Create a test bucket
    bucket = await buckets_service.create_user_bucket(
        cluster_name=cluster,
        org_name=org,
        project_name=project,
        bucket_name="test-bucket",
        org_role=None,
        project_role=None,
    )

    # Create a test credential that references the bucket
    credential = await credentials_service.create_credentials(
        cluster_name=cluster,
        org_name=org,
        project_name=project,
        credential_name="test-credential",
        bucket_ids=[bucket.id],
        org_role=None,
        project_role=None,
    )

    # Verify bucket and credential exist
    assert await buckets_service.get_bucket(bucket.id) is not None
    assert await credentials_service.get_credentials(credential.id) is not None

    # Send project-remove event
    await events_queues.outcome.put(
        RecvEvents(
            subscr_id=uuid.uuid4(),
            events=[
                RecvEvent(
                    tag=Tag("test-tag-123"),
                    timestamp=datetime.now(tz=UTC),
                    sender="platform-admin",
                    stream=StreamType("platform-admin"),
                    event_type=EventType("project-remove"),
                    cluster=cluster,
                    org=org,
                    project=project,
                    user="test-user",
                ),
            ],
        )
    )

    # Wait for the event to be processed
    ack_event = await asyncio.wait_for(events_queues.income.get(), timeout=5.0)
    assert ack_event.events[StreamType("platform-admin")] == ["test-tag-123"]

    # Verify bucket and credential have been deleted
    with pytest.raises(Exception):  # Should raise NotExistsError or similar
        await buckets_service.get_bucket(bucket.id)

    with pytest.raises(Exception):  # Should raise NotExistsError or similar
        await credentials_service.get_credentials(credential.id)


async def test_bucket_deleter_updates_multi_bucket_credentials(
    events_queues: EventsQueues,
    bucket_deleter: BucketDeleter,
    buckets_service: BucketsService,
    credentials_service: PersistentCredentialsService,
) -> None:
    cluster = "test-cluster"
    org = "test-org"
    project = "test-project"
    other_project = "other-project"

    # Create two buckets - one in the project to be deleted, one in another project
    bucket_to_delete = await buckets_service.create_user_bucket(
        cluster_name=cluster,
        org_name=org,
        project_name=project,
        bucket_name="bucket-to-delete",
        org_role=None,
        project_role=None,
    )

    bucket_to_keep = await buckets_service.create_user_bucket(
        cluster_name=cluster,
        org_name=org,
        project_name=other_project,
        bucket_name="bucket-to-keep",
        org_role=None,
        project_role=None,
    )

    # Create a credential that references both buckets
    credential = await credentials_service.create_credentials(
        cluster_name=cluster,
        org_name=org,
        project_name=project,
        credential_name="multi-bucket-credential",
        bucket_ids=[bucket_to_delete.id, bucket_to_keep.id],
        org_role=None,
        project_role=None,
    )

    # Send project-remove event
    await events_queues.outcome.put(
        RecvEvents(
            subscr_id=uuid.uuid4(),
            events=[
                RecvEvent(
                    tag=Tag("test-tag-456"),
                    timestamp=datetime.now(tz=UTC),
                    sender="platform-admin",
                    stream=StreamType("platform-admin"),
                    event_type=EventType("project-remove"),
                    cluster=cluster,
                    org=org,
                    project=project,
                    user="test-user",
                ),
            ],
        )
    )

    # Wait for the event to be processed
    ack_event = await asyncio.wait_for(events_queues.income.get(), timeout=5.0)
    assert ack_event.events[StreamType("platform-admin")] == ["test-tag-456"]

    # Verify the bucket from deleted project is gone
    with pytest.raises(Exception):
        await buckets_service.get_bucket(bucket_to_delete.id)

    # Verify the other bucket still exists
    remaining_bucket = await buckets_service.get_bucket(bucket_to_keep.id)
    assert remaining_bucket is not None

    # Verify credential still exists but only references the remaining bucket
    updated_credential = await credentials_service.get_credentials(credential.id)
    assert updated_credential is not None
    assert bucket_to_delete.id not in updated_credential.bucket_ids
    assert bucket_to_keep.id in updated_credential.bucket_ids


async def test_bucket_deleter_ignores_other_events(
    events_queues: EventsQueues,
    bucket_deleter: BucketDeleter,
    buckets_service: BucketsService,
) -> None:
    cluster = "test-cluster"
    org = "test-org"
    project = "test-project"

    # Create a test bucket
    bucket = await buckets_service.create_user_bucket(
        cluster_name=cluster,
        org_name=org,
        project_name=project,
        bucket_name="test-bucket",
        org_role=None,
        project_role=None,
    )

    # Send a different event type (not project-remove)
    await events_queues.outcome.put(
        RecvEvents(
            subscr_id=uuid.uuid4(),
            events=[
                RecvEvent(
                    tag=Tag("test-tag-789"),
                    timestamp=datetime.now(tz=UTC),
                    sender="platform-admin",
                    stream=StreamType("platform-admin"),
                    event_type=EventType("project-create"),  # Different event type
                    cluster=cluster,
                    org=org,
                    project=project,
                    user="test-user",
                ),
            ],
        )
    )

    # Wait for the event to be processed
    ack_event = await asyncio.wait_for(events_queues.income.get(), timeout=5.0)
    assert ack_event.events[StreamType("platform-admin")] == ["test-tag-789"]

    # Verify bucket still exists (not deleted)
    existing_bucket = await buckets_service.get_bucket(bucket.id)
    assert existing_bucket is not None
    assert existing_bucket.id == bucket.id
