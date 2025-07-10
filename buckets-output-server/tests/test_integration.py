from unittest.mock import AsyncMock, patch

import pytest
from apolo_app_types.protocols.common.buckets import (
    Bucket,
    BucketProvider,
    CredentialsType,
    S3BucketCredentials,
)
from httpx import ASGITransport, AsyncClient
from src.main import app


@pytest.mark.integration
class TestAPIIntegration:
    """Integration tests for the API endpoints."""

    @pytest.mark.asyncio
    async def test_full_outputs_workflow(self):
        """Test the complete outputs workflow with mocked data."""
        # Create sample bucket data
        sample_bucket = Bucket(
            id="test-bucket-1",
            owner="test-user",
            bucket_provider=BucketProvider.AWS,
            credentials=[
                S3BucketCredentials(
                    type=CredentialsType.READ_WRITE,
                    name="test-bucket-1",
                    endpoint_url="https://s3.amazonaws.com",
                    region_name="us-east-1",
                    access_key_id="AKIATEST",
                    secret_access_key="secret123",
                )
            ],
        )

        # Mock the get_buckets function to return our sample data
        with patch("src.main.get_buckets", new_callable=AsyncMock) as mock_get_buckets:
            mock_get_buckets.return_value = [sample_bucket]

            # Mock the authentication dependency
            async def mock_auth():
                return AsyncMock()

            from src.dependencies import dep_get_apolo_client

            app.dependency_overrides[dep_get_apolo_client] = mock_auth

            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                # Test listing outputs
                headers = {"Authorization": "Bearer test-token"}
                response = await client.get("/outputs", headers=headers)

                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "success"
                assert len(data["data"]) == 1
                assert data["data"][0]["id"] == "test-bucket-1"

                # Test getting specific output
                response = await client.get("/outputs/test-bucket-1", headers=headers)
                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "success"
                assert data["data"]["id"] == "test-bucket-1"

                # Test getting non-existent output
                response = await client.get("/outputs/nonexistent", headers=headers)
                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "error"
                assert data["data"] is None

            # Clean up
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_health_endpoints_integration(self):
        """Test all health endpoints work correctly."""
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # Test all health endpoints
            endpoints = ["/", "/health", "/healthz"]

            for endpoint in endpoints:
                response = await client.get(endpoint)
                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_filtering_integration(self):
        """Test filtering functionality end-to-end."""
        # Create multiple sample buckets
        sample_buckets = [
            Bucket(
                id="user1-bucket-1",
                owner="user1",
                bucket_provider=BucketProvider.AWS,
                credentials=[],
            ),
            Bucket(
                id="user1-bucket-2",
                owner="user1",
                bucket_provider=BucketProvider.MINIO,
                credentials=[],
            ),
            Bucket(
                id="user2-bucket-1",
                owner="user2",
                bucket_provider=BucketProvider.GCP,
                credentials=[],
            ),
        ]

        with patch("src.main.get_buckets", new_callable=AsyncMock) as mock_get_buckets:
            mock_get_buckets.return_value = sample_buckets

            # Mock the authentication dependency
            async def mock_auth():
                return AsyncMock()

            from src.dependencies import dep_get_apolo_client

            app.dependency_overrides[dep_get_apolo_client] = mock_auth

            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                headers = {"Authorization": "Bearer test-token"}

                # Test filtering by owner
                response = await client.get("/outputs?filter=user1", headers=headers)
                assert response.status_code == 200
                data = response.json()
                assert len(data["data"]) == 2  # Should get user1's buckets

                # Test filtering by bucket ID
                response = await client.get("/outputs?filter=bucket-1", headers=headers)
                assert response.status_code == 200
                data = response.json()
                assert (
                    len(data["data"]) == 2
                )  # Should get buckets with "bucket-1" in ID

                # Test filtering with no matches
                response = await client.get(
                    "/outputs?filter=nonexistent", headers=headers
                )
                assert response.status_code == 200
                data = response.json()
                assert len(data["data"]) == 0  # Should get no buckets

            # Clean up
            app.dependency_overrides.clear()

    @pytest.mark.asyncio
    async def test_pagination_integration(self):
        """Test pagination functionality end-to-end."""
        # Create multiple sample buckets
        sample_buckets = [
            Bucket(
                id=f"bucket-{i}",
                owner=f"user{i}",
                bucket_provider=BucketProvider.AWS,
                credentials=[],
            )
            for i in range(1, 6)  # 5 buckets
        ]

        with patch("src.main.get_buckets", new_callable=AsyncMock) as mock_get_buckets:
            mock_get_buckets.return_value = sample_buckets

            # Mock the authentication dependency
            async def mock_auth():
                return AsyncMock()

            from src.dependencies import dep_get_apolo_client

            app.dependency_overrides[dep_get_apolo_client] = mock_auth

            transport = ASGITransport(app=app)
            async with AsyncClient(
                transport=transport, base_url="http://test"
            ) as client:
                headers = {"Authorization": "Bearer test-token"}

                # Test first page
                response = await client.get(
                    "/outputs?limit=2&offset=0", headers=headers
                )
                assert response.status_code == 200
                data = response.json()
                assert len(data["data"]) == 2
                first_page_ids = {item["id"] for item in data["data"]}

                # Test second page
                response = await client.get(
                    "/outputs?limit=2&offset=2", headers=headers
                )
                assert response.status_code == 200
                data = response.json()
                assert len(data["data"]) == 2
                second_page_ids = {item["id"] for item in data["data"]}

                # Ensure no overlap between pages
                assert first_page_ids.isdisjoint(second_page_ids)

                # Test last page
                response = await client.get(
                    "/outputs?limit=2&offset=4", headers=headers
                )
                assert response.status_code == 200
                data = response.json()
                assert len(data["data"]) == 1  # Only 1 bucket left

            # Clean up
            app.dependency_overrides.clear()
