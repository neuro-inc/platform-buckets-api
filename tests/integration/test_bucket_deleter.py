from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import uuid4

import aiohttp
import pytest
from apolo_events_client import (
    Ack,
    EventType,
    RecvEvent,
    RecvEvents,
    StreamType,
    Tag,
)
from apolo_events_client.pytest import EventsQueues

from platform_buckets_api.api import create_app
from platform_buckets_api.config import Config

from .auth import UserFactory
from .conftest import create_local_app_server
from .test_api import BucketsApiEndpoints


@pytest.fixture
async def buckets_api(config: Config) -> AsyncIterator[BucketsApiEndpoints]:
    app = await create_app(config)
    async with create_local_app_server(app, port=8080) as address:
        yield BucketsApiEndpoints(address=address)


class TestBucketDeleterIntegration:
    async def test_project_remove_deletes_buckets_and_credentials(
        self,
        client: aiohttp.ClientSession,
        regular_user_factory: UserFactory,
        buckets_api: BucketsApiEndpoints,
        events_queues: EventsQueues,
    ) -> None:
        """Test that project-remove event deletes buckets and their credentials."""
        user = await regular_user_factory(org_name="test-org")

        # Create bucket
        bucket_data = {"name": "test-bucket", "project_name": "test-project"}

        async with client.post(
            buckets_api.buckets_url,
            headers=user.headers,
            json=bucket_data,
        ) as resp:
            assert resp.status == 201
            created_bucket = await resp.json()

        # Create credential for the bucket
        credential_data = {
            "name": "test-credential",
            "bucket_ids": [created_bucket["id"]],
            "read_only": False,
        }

        async with client.post(
            buckets_api.credentials_url,
            headers=user.headers,
            json=credential_data,
        ) as resp:
            assert resp.status == 201
            created_credential = await resp.json()

        # Send project-remove event
        event_tag = "test-delete-project-123"
        await events_queues.outcome.put(
            RecvEvents(
                subscr_id=uuid4(),
                events=[
                    RecvEvent(
                        tag=Tag(event_tag),
                        timestamp=datetime.now(tz=UTC),
                        sender="platform-admin",
                        stream=StreamType("platform-admin"),
                        event_type=EventType("project-remove"),
                        cluster="test-cluster",
                        org="test-org",
                        project="test-project",
                        user="test-user",
                    ),
                ],
            )
        )

        # Wait for event acknowledgment
        ack = await events_queues.income.get()
        assert isinstance(ack, Ack)
        assert ack.events[StreamType("platform-admin")] == [event_tag]

        # Verify bucket is deleted
        async with client.get(
            buckets_api.bucket_url(created_bucket["id"]),
            headers=user.headers,
        ) as resp:
            assert resp.status == 404

        # Verify credential is deleted
        async with client.get(
            buckets_api.credential_url(created_credential["name"]),
            headers=user.headers,
        ) as resp:
            assert resp.status == 404

    async def test_ignores_non_project_remove_events(
        self,
        client: aiohttp.ClientSession,
        regular_user_factory: UserFactory,
        buckets_api: BucketsApiEndpoints,
        events_queues: EventsQueues,
    ) -> None:
        """Test that non-project-remove events are ignored but acknowledged."""
        user = await regular_user_factory(org_name="test-org")

        # Create bucket
        bucket_data = {"name": "ignore-test-bucket", "project_name": "test-project"}

        async with client.post(
            buckets_api.buckets_url,
            headers=user.headers,
            json=bucket_data,
        ) as resp:
            assert resp.status == 201
            created_bucket = await resp.json()

        # Send project-create event (should be ignored)
        event_tag = "ignore-event-111"
        await events_queues.outcome.put(
            RecvEvents(
                subscr_id=uuid4(),
                events=[
                    RecvEvent(
                        tag=Tag(event_tag),
                        timestamp=datetime.now(tz=UTC),
                        sender="platform-admin",
                        stream=StreamType("platform-admin"),
                        event_type=EventType("project-create"),
                        cluster="test-cluster",
                        org="test-org",
                        project="test-project",
                        user="test-user",
                    ),
                ],
            )
        )

        # Wait for acknowledgment (event should still be acked)
        ack = await events_queues.income.get()
        assert isinstance(ack, Ack)
        assert ack.events[StreamType("platform-admin")] == [event_tag]

        # Verify bucket still exists
        async with client.get(
            buckets_api.bucket_url(created_bucket["id"]),
            headers=user.headers,
        ) as resp:
            assert resp.status == 200

    async def test_project_isolation(
        self,
        client: aiohttp.ClientSession,
        regular_user_factory: UserFactory,
        buckets_api: BucketsApiEndpoints,
        events_queues: EventsQueues,
    ) -> None:
        """Test that only buckets from specified project are deleted."""
        user = await regular_user_factory(org_name="test-org")

        # Create bucket in project to be deleted
        bucket_to_delete_data = {
            "name": "bucket-to-delete",
            "project_name": "project-to-delete",
        }

        async with client.post(
            buckets_api.buckets_url,
            headers=user.headers,
            json=bucket_to_delete_data,
        ) as resp:
            assert resp.status == 201
            bucket_to_delete = await resp.json()

        # Create bucket in project to keep
        bucket_to_keep_data = {
            "name": "bucket-to-keep",
            "project_name": "project-to-keep",
        }

        async with client.post(
            buckets_api.buckets_url,
            headers=user.headers,
            json=bucket_to_keep_data,
        ) as resp:
            assert resp.status == 201
            bucket_to_keep = await resp.json()

        # Send project-remove event for specific project
        event_tag = "isolation-test-222"
        await events_queues.outcome.put(
            RecvEvents(
                subscr_id=uuid4(),
                events=[
                    RecvEvent(
                        tag=Tag(event_tag),
                        timestamp=datetime.now(tz=UTC),
                        sender="platform-admin",
                        stream=StreamType("platform-admin"),
                        event_type=EventType("project-remove"),
                        cluster="test-cluster",
                        org="test-org",
                        project="project-to-delete",
                        user="test-user",
                    ),
                ],
            )
        )

        # Wait for acknowledgment
        ack = await events_queues.income.get()
        assert isinstance(ack, Ack)
        assert ack.events[StreamType("platform-admin")] == [event_tag]

        # Verify bucket in deleted project is gone
        async with client.get(
            buckets_api.bucket_url(bucket_to_delete["id"]),
            headers=user.headers,
        ) as resp:
            assert resp.status == 404

        # Verify bucket in kept project still exists
        async with client.get(
            buckets_api.bucket_url(bucket_to_keep["id"]),
            headers=user.headers,
        ) as resp:
            assert resp.status == 200
