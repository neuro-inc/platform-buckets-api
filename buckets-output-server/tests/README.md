# Buckets Output Server Tests

This directory contains comprehensive tests for the FastAPI buckets output server.

## Test Structure

- `test_api.py` - Tests for API endpoints (health checks, outputs listing, single output retrieval)
- `test_models.py` - Tests for Pydantic models and validation
- `test_utils.py` - Tests for utility functions (filtering, bucket mapping)
- `test_integration.py` - Integration tests for complete workflows
- `conftest.py` - Test configuration and fixtures

## Running Tests

### Run all tests:
```bash
poetry run pytest
```

### Run specific test file:
```bash
poetry run pytest tests/test_api.py
```

### Run tests with coverage:
```bash
poetry run pytest --cov=src
```

### Run only unit tests:
```bash
poetry run pytest -m "not integration"
```

### Run only integration tests:
```bash
poetry run pytest -m integration
```

## Test Features

### API Endpoint Tests
- Health check endpoints (`/`, `/health`, `/healthz`)
- Outputs listing endpoint (`/outputs`) with filtering and pagination
- Single output retrieval (`/outputs/{bucket_id}`)
- Authentication and authorization testing
- Error handling scenarios

### Model Tests
- Pydantic model validation
- Request/response serialization
- Field validation (limits, offsets, filters)

### Utility Tests
- Bucket filtering functionality
- Credential mapping
- Case-insensitive search

### Integration Tests
- End-to-end workflow testing
- Complete request/response cycles
- Filtering and pagination workflows

## Test Configuration

Tests use:
- **pytest** for test framework
- **httpx.AsyncClient** with **ASGITransport** for API testing
- **unittest.mock** for mocking dependencies
- **pytest-asyncio** for async test support

## Mocking Strategy

Tests mock:
- Apolo SDK client (`apolo_sdk.Client`)
- Authentication dependencies
- Bucket and credential data
- External API calls

This ensures tests run quickly and reliably without external dependencies.
