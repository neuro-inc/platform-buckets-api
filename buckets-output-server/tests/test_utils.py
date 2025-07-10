from unittest.mock import MagicMock

from apolo_app_types.protocols.common.buckets import (
    Bucket,
    BucketProvider,
)
from src.utils import (
    bucket_credentials_map,
    filter_bucket_name,
    filter_buckets,
)


class TestBucketCredentialsMap:
    """Test bucket credentials mapping functionality."""

    def test_bucket_credentials_map_empty(self):
        """Test mapping with empty lists."""
        result = bucket_credentials_map([], [])
        assert result == []

    def test_bucket_credentials_map_no_credentials(self):
        """Test mapping with buckets but no credentials."""
        mock_bucket = MagicMock()
        mock_bucket.id = "bucket-1"

        result = bucket_credentials_map([mock_bucket], [])
        assert len(result) == 1
        assert result[0]["bucket"] == mock_bucket
        assert result[0]["credentials"] == []

    def test_bucket_credentials_map_with_credentials(self):
        """Test mapping with buckets and matching credentials."""
        mock_bucket = MagicMock()
        mock_bucket.id = "bucket-1"

        mock_cred_item = MagicMock()
        mock_cred_item.bucket_id = "bucket-1"

        mock_credential = MagicMock()
        mock_credential.credentials = [mock_cred_item]

        result = bucket_credentials_map([mock_bucket], [mock_credential])
        assert len(result) == 1
        assert result[0]["bucket"] == mock_bucket
        assert result[0]["credentials"] == [mock_credential]

    def test_bucket_credentials_map_multiple_credentials_per_bucket(self):
        """Test mapping with multiple credentials for the same bucket."""
        mock_bucket = MagicMock()
        mock_bucket.id = "bucket-1"

        mock_cred_item1 = MagicMock()
        mock_cred_item1.bucket_id = "bucket-1"
        mock_cred_item2 = MagicMock()
        mock_cred_item2.bucket_id = "bucket-1"

        mock_credential1 = MagicMock()
        mock_credential1.credentials = [mock_cred_item1]
        mock_credential2 = MagicMock()
        mock_credential2.credentials = [mock_cred_item2]

        result = bucket_credentials_map(
            [mock_bucket], [mock_credential1, mock_credential2]
        )
        assert len(result) == 1
        assert result[0]["bucket"] == mock_bucket
        assert len(result[0]["credentials"]) == 2


class TestFilterBucketName:
    """Test bucket name filtering functionality."""

    def test_filter_bucket_name_empty_query(self):
        """Test filtering with empty query returns True."""
        mock_cred = MagicMock()
        mock_cred.name = "test-bucket"

        result = filter_bucket_name("", [mock_cred])
        assert result is True

    def test_filter_bucket_name_matching(self):
        """Test filtering with matching query."""
        mock_cred = MagicMock()
        mock_cred.name = "test-bucket"

        result = filter_bucket_name("test", [mock_cred])
        assert result is True

    def test_filter_bucket_name_not_matching(self):
        """Test filtering with non-matching query."""
        mock_cred = MagicMock()
        mock_cred.name = "production-bucket"

        result = filter_bucket_name("test", [mock_cred])
        assert result is False

    def test_filter_bucket_name_case_insensitive(self):
        """Test filtering is case insensitive."""
        mock_cred = MagicMock()
        mock_cred.name = "Test-Bucket"

        result = filter_bucket_name("test", [mock_cred])
        assert result is True

    def test_filter_bucket_name_no_name_attribute(self):
        """Test filtering with credentials that don't have name attribute."""
        mock_cred = MagicMock()
        del mock_cred.name  # Remove name attribute

        result = filter_bucket_name("test", [mock_cred])
        assert result is False


class TestFilterBuckets:
    """Test bucket filtering functionality."""

    def test_filter_buckets_no_query(self):
        """Test filtering with no query returns all buckets."""
        bucket1 = Bucket(
            id="bucket-1",
            owner="user1",
            bucket_provider=BucketProvider.AWS,
            credentials=[],
        )
        bucket2 = Bucket(
            id="bucket-2",
            owner="user2",
            bucket_provider=BucketProvider.AWS,
            credentials=[],
        )

        buckets = [bucket1, bucket2]
        result = filter_buckets(buckets, None)
        assert len(result) == 2
        assert result == buckets

    def test_filter_buckets_by_id(self):
        """Test filtering buckets by ID."""
        bucket1 = Bucket(
            id="test-bucket-1",
            owner="user1",
            bucket_provider=BucketProvider.AWS,
            credentials=[],
        )
        bucket2 = Bucket(
            id="prod-bucket-2",
            owner="user2",
            bucket_provider=BucketProvider.AWS,
            credentials=[],
        )

        buckets = [bucket1, bucket2]
        result = filter_buckets(buckets, "test")
        assert len(result) == 1
        assert result[0] == bucket1

    def test_filter_buckets_by_owner(self):
        """Test filtering buckets by owner."""
        bucket1 = Bucket(
            id="bucket-1",
            owner="alice",
            bucket_provider=BucketProvider.AWS,
            credentials=[],
        )
        bucket2 = Bucket(
            id="bucket-2",
            owner="bob",
            bucket_provider=BucketProvider.AWS,
            credentials=[],
        )

        buckets = [bucket1, bucket2]
        result = filter_buckets(buckets, "alice")
        assert len(result) == 1
        assert result[0] == bucket1

    def test_filter_buckets_case_insensitive(self):
        """Test filtering is case insensitive."""
        bucket = Bucket(
            id="Test-Bucket",
            owner="User1",
            bucket_provider=BucketProvider.AWS,
            credentials=[],
        )

        buckets = [bucket]
        result = filter_buckets(buckets, "test")
        assert len(result) == 1
        assert result[0] == bucket

    def test_filter_buckets_no_matches(self):
        """Test filtering with no matches returns empty list."""
        bucket = Bucket(
            id="bucket-1",
            owner="user1",
            bucket_provider=BucketProvider.AWS,
            credentials=[],
        )

        buckets = [bucket]
        result = filter_buckets(buckets, "nonexistent")
        assert len(result) == 0
