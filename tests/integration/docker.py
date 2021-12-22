import os
from collections.abc import Iterator
from typing import Any

import pytest
from docker import DockerClient


PYTEST_REUSE_DOCKER_OPT = "--reuse-docker"


def pytest_addoption(parser: Any) -> None:
    parser.addoption(
        PYTEST_REUSE_DOCKER_OPT,
        action="store_true",
        help="Reuse existing docker containers",
    )


@pytest.fixture(scope="session")
def reuse_docker(request: Any) -> bool:
    return bool(request.config.getoption(PYTEST_REUSE_DOCKER_OPT))


@pytest.fixture(scope="session")
def in_docker() -> bool:
    return os.path.isfile("/.dockerenv")


@pytest.fixture(scope="session")
def docker_client() -> Iterator[DockerClient]:
    client = DockerClient()
    yield client
    client.close()
