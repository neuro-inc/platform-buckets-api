from datetime import UTC, datetime
from typing import cast

from apolo_events_client import EventType, RecvEvent, StreamType, Tag

from platform_buckets_api.project_deleter import ProjectDeleter
from platform_buckets_api.service import BucketsService, PersistentCredentialsService


def make_event(event_type: str, cluster: str) -> RecvEvent:
    return RecvEvent(
        tag=Tag("1"),
        timestamp=datetime.now(tz=UTC),
        sender="platform-admin",
        stream=StreamType("platform-admin"),
        event_type=EventType(event_type),
        cluster=cluster,
        org="org",
        project="project",
        user="user",
    )


class RecordingDeleter(ProjectDeleter):
    def __init__(self, cluster_name: str) -> None:
        super().__init__(
            None,
            cast(BucketsService, object()),
            cast(PersistentCredentialsService, object()),
            cluster_name,
        )
        self.processed: list[RecvEvent] = []

    async def _process_project_deletion(self, ev: RecvEvent) -> None:
        self.processed.append(ev)


async def test_processes_project_of_own_cluster() -> None:
    deleter = RecordingDeleter("apolo-main")
    ev = make_event("project-remove", "apolo-main")

    await deleter._on_admin_event(ev)

    assert deleter.processed == [ev]


async def test_ignores_project_of_other_cluster() -> None:
    deleter = RecordingDeleter("apolo-main")

    await deleter._on_admin_event(make_event("project-remove", "alfa"))

    assert deleter.processed == []


async def test_ignores_other_event_types() -> None:
    deleter = RecordingDeleter("apolo-main")

    await deleter._on_admin_event(make_event("project-create", "apolo-main"))

    assert deleter.processed == []
