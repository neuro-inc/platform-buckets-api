from unittest.mock import AsyncMock, MagicMock
from datetime import UTC, datetime

import pytest
from apolo_events_client import (
    EventType,
    EventsClientConfig,
    RecvEvent,
    StreamType,
    Tag,
)
from yarl import URL

from platform_buckets_api.bucket_deleter import BucketDeleter
from platform_buckets_api.service import BucketsService, PersistentCredentialsService
from platform_buckets_api.storage import UserBucket, PersistentCredentials


@pytest.fixture
def events_config() -> EventsClientConfig:
    return EventsClientConfig(
        url=URL("http://test-events:8080/apis/events"),
        token="test-token",
        name="platform-buckets",
    )


@pytest.fixture
def mock_buckets_service() -> BucketsService:
    service = MagicMock(spec=BucketsService)
    service.get_buckets = AsyncMock()
    service.delete_bucket = AsyncMock()
    return service


@pytest.fixture
def mock_credentials_service() -> PersistentCredentialsService:
    service = MagicMock(spec=PersistentCredentialsService)
    service.list_credentials_with_bucket = AsyncMock()
    service.delete_credentials = AsyncMock()
    service.update_credentials = AsyncMock()
    return service


class TestBucketDeleter:
    async def test_project_remove_event_processing(
        self,
        events_config: EventsClientConfig,
        mock_buckets_service: BucketsService,
        mock_credentials_service: PersistentCredentialsService,
    ) -> None:
        """Test that project-remove events trigger bucket deletion."""
        # Setup test data
        test_bucket = UserBucket(
            id="bucket-123",
            name="test-bucket",
            owner="test-user",
            org_name="test-org",
            project_name="test-project",
            provider_bucket=MagicMock(),
            public=False,
            created_at=datetime.now(tz=UTC),
        )

        test_credential = PersistentCredentials(
            id="cred-456",
            name="test-credential",
            owner="test-user",
            bucket_ids=["bucket-123"],
            role=MagicMock(),
            read_only=False,
            namespace="test-namespace",
        )

        # Mock bucket storage to return our test bucket
        async def mock_list_buckets(org_name, project_name):
            if org_name == "test-org" and project_name == "test-project":
                yield test_bucket

        mock_buckets_service._storage = MagicMock()
        mock_buckets_service._storage.list_buckets.side_effect = mock_list_buckets

        # Mock credentials service to return our test credential
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_list_credentials_with_bucket(bucket_id):
            async def mock_iterator():
                if bucket_id == "bucket-123":
                    yield test_credential

            yield mock_iterator()

        mock_credentials_service.list_credentials_with_bucket = (
            mock_list_credentials_with_bucket
        )

        # Create BucketDeleter instance
        deleter = BucketDeleter(
            config=events_config,
            buckets_service=mock_buckets_service,
            credentials_service=mock_credentials_service,
        )

        # Create test event
        test_event = RecvEvent(
            tag=Tag("test-tag-123"),
            timestamp=datetime.now(tz=UTC),
            sender="platform-admin",
            stream=StreamType("platform-admin"),
            event_type=EventType("project-remove"),
            cluster="test-cluster",
            org="test-org",
            project="test-project",
            user="test-user",
        )

        # Process the event directly
        await deleter._process_project_deletion(test_event)

        # Verify that buckets were queried correctly
        mock_buckets_service._storage.list_buckets.assert_called_once_with(
            org_name="test-org", project_name="test-project"
        )

        # Verify that credentials were deleted
        mock_credentials_service.delete_credentials.assert_called_once_with(
            test_credential
        )

        # Verify that bucket was deleted
        mock_buckets_service.delete_bucket.assert_called_once_with("bucket-123")

    async def test_multi_bucket_credential_update(
        self,
        events_config: EventsClientConfig,
        mock_buckets_service: BucketsService,
        mock_credentials_service: PersistentCredentialsService,
    ) -> None:
        """Test that multi-bucket credentials are updated, not deleted."""
        # Setup test data
        test_bucket = UserBucket(
            id="bucket-to-delete",
            name="test-bucket",
            owner="test-user",
            org_name="test-org",
            project_name="test-project",
            provider_bucket=MagicMock(),
            public=False,
            created_at=datetime.now(tz=UTC),
        )

        multi_bucket_credential = PersistentCredentials(
            id="cred-456",
            name="multi-bucket-credential",
            owner="test-user",
            bucket_ids=["bucket-to-delete", "bucket-to-keep"],
            role=MagicMock(),
            read_only=False,
            namespace="test-namespace",
        )

        # Mock services
        async def mock_list_buckets(org_name, project_name):
            if org_name == "test-org" and project_name == "test-project":
                yield test_bucket

        mock_buckets_service._storage = MagicMock()
        mock_buckets_service._storage.list_buckets.side_effect = mock_list_buckets

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_list_credentials_with_bucket(bucket_id):
            async def mock_iterator():
                if bucket_id == "bucket-to-delete":
                    yield multi_bucket_credential

            yield mock_iterator()

        mock_credentials_service.list_credentials_with_bucket = (
            mock_list_credentials_with_bucket
        )

        # Create BucketDeleter instance
        deleter = BucketDeleter(
            config=events_config,
            buckets_service=mock_buckets_service,
            credentials_service=mock_credentials_service,
        )

        # Create test event
        test_event = RecvEvent(
            tag=Tag("test-tag-456"),
            timestamp=datetime.now(tz=UTC),
            sender="platform-admin",
            stream=StreamType("platform-admin"),
            event_type=EventType("project-remove"),
            cluster="test-cluster",
            org="test-org",
            project="test-project",
            user="test-user",
        )

        # Process the event
        await deleter._process_project_deletion(test_event)

        # Verify that credentials were updated, not deleted
        mock_credentials_service.update_credentials.assert_called_once_with(
            multi_bucket_credential,
            bucket_ids=["bucket-to-keep"],
            read_only=False,
        )
        mock_credentials_service.delete_credentials.assert_not_called()

        # Verify that bucket was still deleted
        mock_buckets_service.delete_bucket.assert_called_once_with("bucket-to-delete")

    async def test_ignores_non_project_remove_events(
        self,
        events_config: EventsClientConfig,
        mock_buckets_service: BucketsService,
        mock_credentials_service: PersistentCredentialsService,
    ) -> None:
        """Test that non-project-remove events are ignored."""
        # Create BucketDeleter instance
        deleter = BucketDeleter(
            config=events_config,
            buckets_service=mock_buckets_service,
            credentials_service=mock_credentials_service,
        )

        # Create test event with different event type
        test_event = RecvEvent(
            tag=Tag("test-tag-789"),
            timestamp=datetime.now(tz=UTC),
            sender="platform-admin",
            stream=StreamType("platform-admin"),
            event_type=EventType("project-create"),  # Different event type
            cluster="test-cluster",
            org="test-org",
            project="test-project",
            user="test-user",
        )

        # Process the event through the event handler
        await deleter._on_admin_event(test_event)

        # Verify that no service methods were called
        mock_credentials_service.delete_credentials.assert_not_called()
        mock_buckets_service.delete_bucket.assert_not_called()

    async def test_error_handling_during_deletion(
        self,
        events_config: EventsClientConfig,
        mock_buckets_service: BucketsService,
        mock_credentials_service: PersistentCredentialsService,
    ) -> None:
        """Test that errors during deletion don't prevent other buckets from being processed."""
        # Setup test data
        bucket1 = UserBucket(
            id="bucket-1",
            name="bucket-1",
            owner="test-user",
            org_name="test-org",
            project_name="test-project",
            provider_bucket=MagicMock(),
            public=False,
            created_at=datetime.now(tz=UTC),
        )

        bucket2 = UserBucket(
            id="bucket-2",
            name="bucket-2",
            owner="test-user",
            org_name="test-org",
            project_name="test-project",
            provider_bucket=MagicMock(),
            public=False,
            created_at=datetime.now(tz=UTC),
        )

        # Mock bucket service to return both buckets
        async def mock_list_buckets(org_name, project_name):
            yield bucket1
            yield bucket2

        mock_buckets_service._storage = MagicMock()
        mock_buckets_service._storage.list_buckets.side_effect = mock_list_buckets

        # Mock credentials service to not find any credentials
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def mock_list_credentials_with_bucket(bucket_id):
            async def mock_iterator():
                return
                yield  # This won't execute

            yield mock_iterator()

        mock_credentials_service.list_credentials_with_bucket = (
            mock_list_credentials_with_bucket
        )

        # Make bucket deletion fail for the first bucket
        def mock_delete_bucket(bucket_id):
            if bucket_id == "bucket-1":
                raise Exception("Simulated deletion error")

        mock_buckets_service.delete_bucket.side_effect = mock_delete_bucket

        # Create BucketDeleter instance
        deleter = BucketDeleter(
            config=events_config,
            buckets_service=mock_buckets_service,
            credentials_service=mock_credentials_service,
        )

        # Create test event
        test_event = RecvEvent(
            tag=Tag("test-tag-error"),
            timestamp=datetime.now(tz=UTC),
            sender="platform-admin",
            stream=StreamType("platform-admin"),
            event_type=EventType("project-remove"),
            cluster="test-cluster",
            org="test-org",
            project="test-project",
            user="test-user",
        )

        # Process the event - should not raise exception
        await deleter._process_project_deletion(test_event)

        # Verify both bucket deletions were attempted
        assert mock_buckets_service.delete_bucket.call_count == 2
        mock_buckets_service.delete_bucket.assert_any_call("bucket-1")
        mock_buckets_service.delete_bucket.assert_any_call("bucket-2")
