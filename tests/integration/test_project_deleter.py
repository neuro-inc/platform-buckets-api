import asyncio
from datetime import UTC, datetime
from uuid import uuid4

import aiohttp
from apolo_events_client import (
    Ack,
    EventType,
    RecvEvent,
    RecvEvents,
    StreamType,
    Tag,
)
from apolo_events_client.pytest import EventsQueues

from .auth import UserFactory
from .conftest import BucketsApiEndpoints


class TestProjectDeleterIntegration:
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
        bucket_data = {
            "name": "test-bucket",
            "project_name": "test-project",
            "org_name": "test-org",
        }

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
        ack = await asyncio.wait_for(events_queues.income.get(), timeout=1.0)
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
        bucket_data = {
            "name": "ignore-test-bucket",
            "project_name": "test-project",
            "org_name": "test-org",
        }

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
        ack = await asyncio.wait_for(events_queues.income.get(), timeout=1.0)
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
        # Use two different orgs to simulate project isolation
        user_org1 = await regular_user_factory(org_name="test-org1")
        user_org2 = await regular_user_factory(org_name="test-org2")

        # Create bucket in first org (will be "deleted")
        bucket_to_delete_data = {
            "name": "bucket-to-delete",
            "project_name": "test-project",
            "org_name": "test-org1",
        }

        async with client.post(
            buckets_api.buckets_url,
            headers=user_org1.headers,
            json=bucket_to_delete_data,
        ) as resp:
            assert resp.status == 201
            bucket_to_delete = await resp.json()

        # Create bucket in second org (should be kept)
        bucket_to_keep_data = {
            "name": "bucket-to-keep",
            "project_name": "test-project",
            "org_name": "test-org2",
        }

        async with client.post(
            buckets_api.buckets_url,
            headers=user_org2.headers,
            json=bucket_to_keep_data,
        ) as resp:
            assert resp.status == 201
            bucket_to_keep = await resp.json()

        # Send project-remove event for first org only
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
                        org="test-org1",
                        project="test-project",
                        user="test-user",
                    ),
                ],
            )
        )

        # Wait for acknowledgment
        ack = await asyncio.wait_for(events_queues.income.get(), timeout=1.0)
        assert isinstance(ack, Ack)
        assert ack.events[StreamType("platform-admin")] == [event_tag]

        # Verify bucket in deleted org is gone
        async with client.get(
            buckets_api.bucket_url(bucket_to_delete["id"]),
            headers=user_org1.headers,
        ) as resp:
            assert resp.status == 404

        # Verify bucket in kept org still exists
        async with client.get(
            buckets_api.bucket_url(bucket_to_keep["id"]),
            headers=user_org2.headers,
        ) as resp:
            assert resp.status == 200
