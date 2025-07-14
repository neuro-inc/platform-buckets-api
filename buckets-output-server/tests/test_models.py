import pytest
from pydantic import ValidationError

from apolo_app_types.protocols.common.buckets import (
    Bucket,
    BucketProvider,
)
from src.models import (
    BasicResponse,
    BucketResponse,
    FilterParams,
    IdResponse,
    ListResponse,
)


class TestIdResponse:
    """Test IdResponse model."""

    def test_id_response_creation(self):
        """Test creating IdResponse with valid data."""
        bucket = Bucket(
            id="bucket-1",
            owner="user1",
            bucket_provider=BucketProvider.AWS,
            credentials=[],
        )

        response = IdResponse(id="bucket-1", value=bucket)
        assert response.id == "bucket-1"
        assert response.value == bucket

    def test_id_response_serialization(self):
        """Test IdResponse serialization."""
        bucket = Bucket(
            id="bucket-1",
            owner="user1",
            bucket_provider=BucketProvider.AWS,
            credentials=[],
        )

        response = IdResponse(id="bucket-1", value=bucket)
        data = response.model_dump()

        assert data["id"] == "bucket-1"
        assert "value" in data
        assert data["value"]["id"] == "bucket-1"


class TestBasicResponse:
    """Test BasicResponse model."""

    def test_basic_response_status_only(self):
        """Test creating BasicResponse with status only."""
        response = BasicResponse(status="healthy")
        assert response.status == "healthy"
        assert response.data is None

    def test_basic_response_with_data(self):
        """Test creating BasicResponse with data."""
        test_data = {"key": "value"}
        response = BasicResponse(status="success", data=test_data)
        assert response.status == "success"
        assert response.data == test_data

    def test_basic_response_with_list_data(self):
        """Test creating BasicResponse with list data."""
        test_data = [{"key1": "value1"}, {"key2": "value2"}]
        response = BasicResponse(status="success", data=test_data)
        assert response.status == "success"
        assert response.data == test_data


class TestListResponse:
    """Test ListResponse model."""

    def test_list_response_empty(self):
        """Test creating empty ListResponse."""
        response = ListResponse(status="success")
        assert response.status == "success"
        assert response.data is None

    def test_list_response_with_data(self):
        """Test creating ListResponse with data."""
        bucket = Bucket(
            id="bucket-1",
            owner="user1",
            bucket_provider=BucketProvider.AWS,
            credentials=[],
        )

        id_response = IdResponse(id="bucket-1", value=bucket)
        response = ListResponse(status="success", data=[id_response])

        assert response.status == "success"
        assert response.data is not None
        assert len(response.data) == 1
        assert response.data[0].id == "bucket-1"


class TestBucketResponse:
    """Test BucketResponse model."""

    def test_bucket_response_success(self):
        """Test creating successful BucketResponse."""
        bucket = Bucket(
            id="bucket-1",
            owner="user1",
            bucket_provider=BucketProvider.AWS,
            credentials=[],
        )

        response = BucketResponse(status="success", data=bucket)
        assert response.status == "success"
        assert response.data == bucket

    def test_bucket_response_error(self):
        """Test creating error BucketResponse."""
        response = BucketResponse(status="error", data=None)
        assert response.status == "error"
        assert response.data is None


class TestFilterParams:
    """Test FilterParams model."""

    def test_filter_params_defaults(self):
        """Test FilterParams with default values."""
        params = FilterParams(limit=10, offset=0)
        assert params.filter is None
        assert params.limit == 10
        assert params.offset == 0

    def test_filter_params_custom_values(self):
        """Test FilterParams with custom values."""
        params = FilterParams(filter="test", limit=50, offset=20)
        assert params.filter == "test"
        assert params.limit == 50
        assert params.offset == 20

    def test_filter_params_validation_limit_too_high(self):
        """Test FilterParams validation for limit too high."""
        with pytest.raises(ValidationError) as exc_info:
            FilterParams(limit=101, offset=0)

        errors = exc_info.value.errors()
        assert any(error["type"] == "less_than_equal" for error in errors)

    def test_filter_params_validation_limit_zero(self):
        """Test FilterParams validation for limit zero."""
        with pytest.raises(ValidationError) as exc_info:
            FilterParams(limit=0, offset=0)

        errors = exc_info.value.errors()
        assert any(error["type"] == "greater_than" for error in errors)

    def test_filter_params_validation_limit_negative(self):
        """Test FilterParams validation for negative limit."""
        with pytest.raises(ValidationError) as exc_info:
            FilterParams(limit=-1, offset=0)

        errors = exc_info.value.errors()
        assert any(error["type"] == "greater_than" for error in errors)

    def test_filter_params_validation_offset_negative(self):
        """Test FilterParams validation for negative offset."""
        with pytest.raises(ValidationError) as exc_info:
            FilterParams(limit=10, offset=-1)

        errors = exc_info.value.errors()
        assert any(error["type"] == "greater_than_equal" for error in errors)

    def test_filter_params_validation_valid_edge_cases(self):
        """Test FilterParams validation for valid edge cases."""
        # Test minimum valid limit
        params = FilterParams(limit=1, offset=0)
        assert params.limit == 1

        # Test maximum valid limit
        params = FilterParams(limit=100, offset=0)
        assert params.limit == 100

        # Test minimum valid offset
        params = FilterParams(limit=10, offset=0)
        assert params.offset == 0

    def test_filter_params_serialization(self):
        """Test FilterParams serialization."""
        params = FilterParams(filter="test", limit=25, offset=10)
        data = params.model_dump()

        assert data["filter"] == "test"
        assert data["limit"] == 25
        assert data["offset"] == 10

    def test_filter_params_from_dict(self):
        """Test creating FilterParams from dictionary."""
        data = {"filter": "search", "limit": 30, "offset": 5}
        params = FilterParams(**data)

        assert params.filter == "search"
        assert params.limit == 30
        assert params.offset == 5
