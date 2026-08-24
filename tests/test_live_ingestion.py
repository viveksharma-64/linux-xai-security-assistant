import sys
import threading
import time

from api.app import create_app
from fastapi.testclient import TestClient
from pipeline.event_stream import CanonicalNormalizer
from pipeline.live_ingestion import (
    DatabaseAnalysisPipeline,
    LiveIngestionService,
    SubprocessJSONLSource,
)
from storage.sqlite_store import SQLiteEventStore


def _event(timestamp=1000.0, pid=1, comm="bash"):
    return {
        "event_type": "process_exec",
        "timestamp": timestamp,
        "pid": pid,
        "uid": 1000,
        "gid": 1000,
        "comm": comm,
        "filename": "/usr/bin/" + comm,
        "source": "test_source",
        "version": "1.0",
    }


def test_ingestion_isolates_malformed_records_and_deduplicates_sqlite(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "ingestion.db"))
    source = [_event(), "not-json", {"event_type": "unknown", "timestamp": 1001}, _event()]

    health = LiveIngestionService(source, store).run()

    assert health.status == "stopped"
    assert health.processed_count == 2
    assert health.duplicate_count == 1
    assert health.malformed_count == 2
    assert health.dropped_event_count == 0
    assert store.count_events() == 1
    assert store.read_collector_health()["status"] == "stopped"


def test_bounded_queue_counts_backpressure_drops(tmp_path):
    started = threading.Event()
    release = threading.Event()

    class BlockingNormalizer(CanonicalNormalizer):
        calls = 0

        def normalize(self, raw_event):
            self.calls += 1
            if self.calls == 1:
                started.set()
                release.wait(timeout=2)
            return super().normalize(raw_event)

    store = SQLiteEventStore(str(tmp_path / "backpressure.db"))
    service = LiveIngestionService(
        [_event(timestamp=1000 + index, pid=index) for index in range(40)],
        store,
        queue_size=1,
        normalizer=BlockingNormalizer(),
    )
    service.start()
    assert started.wait(timeout=2)
    deadline = time.time() + 2
    while service.health().dropped_event_count == 0 and time.time() < deadline:
        time.sleep(0.01)
    release.set()
    assert service._producer is not None
    assert service._consumer is not None
    service._producer.join(timeout=3)
    service._consumer.join(timeout=3)

    assert service.health().dropped_event_count > 0
    assert service.health().status == "stopped"


def test_graceful_shutdown_stops_a_live_source(tmp_path):
    closed = threading.Event()

    def source():
        index = 0
        while not closed.is_set():
            yield _event(timestamp=1000 + index, pid=index)
            index += 1
            time.sleep(0.001)

    class ClosableSource:
        def __iter__(self):
            yield from source()

        def close(self):
            closed.set()

    service = LiveIngestionService(ClosableSource(), SQLiteEventStore(str(tmp_path / "shutdown.db")))
    service.start()
    deadline = time.time() + 2
    while service.health().processed_count == 0 and time.time() < deadline:
        time.sleep(0.01)
    service.stop()
    assert service._producer is not None
    assert service._consumer is not None
    service._producer.join(timeout=3)
    service._consumer.join(timeout=3)

    assert not service._producer.is_alive()
    assert not service._consumer.is_alive()
    assert service.health().status == "stopped"


def test_subprocess_failure_is_recorded_as_collector_error(tmp_path):
    source = SubprocessJSONLSource([
        sys.executable,
        "-c",
        "import sys; print('collector failed', file=sys.stderr); sys.exit(3)",
    ])
    health = LiveIngestionService(source, SQLiteEventStore(str(tmp_path / "failure.db"))).run()

    assert health.status == "failed"
    assert "status 3" in health.error
    assert "collector failed" in health.error


def test_subprocess_shutdown_is_clean_and_service_can_restart(tmp_path):
    source = SubprocessJSONLSource([
        sys.executable,
        "-u",
        "-c",
        "import json, time; print(json.dumps({'event_type':'process_exec','timestamp':1000,'pid':1,'uid':1000,'comm':'sleep'}), flush=True); time.sleep(10)",
    ])
    store = SQLiteEventStore(str(tmp_path / "restart.db"))
    service = LiveIngestionService(source, store)
    service.start()
    deadline = time.time() + 2
    while service.health().processed_count == 0 and time.time() < deadline:
        time.sleep(0.01)
    service.stop()
    assert service._producer is not None
    assert service._consumer is not None
    service._producer.join(timeout=3)
    service._consumer.join(timeout=3)
    assert service.health().status == "stopped"

    restarted = service.run()
    assert restarted.status == "stopped"
    assert restarted.duplicate_count == 1
    assert store.count_events() == 1


def test_live_analysis_does_not_promote_monitoring_events_to_baseline(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "analysis.db"))
    analysis = DatabaseAnalysisPipeline(store).process
    health = LiveIngestionService(
        [_event(timestamp=1000 + index, pid=index, comm="nc") for index in range(4)],
        store,
        analysis_pipeline=analysis,
    ).run()

    assert health.status == "stopped"
    assert store.read_latest_ready_baseline() is None
    assert store.read_detection_findings() == []


def test_api_reports_persisted_supervisor_health(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "api.db"))
    store.write_collector_health({
        "status": "running",
        "detail": "collector active",
        "processed_count": 4,
        "malformed_count": 1,
        "dropped_event_count": 2,
        "duplicate_count": 1,
        "throughput": 2.5,
        "updated_at": 1000.0,
    })
    response = TestClient(create_app(store)).get("/api/status")

    assert response.status_code == 200
    data = response.json()
    assert data["collector_status"] == "running"
    assert data["collector_detail"] == "collector active"
    assert data["collector_processed_count"] == 4
    assert data["collector_malformed_count"] == 1
    assert data["dropped_event_count"] == 2
    assert data["collector_throughput"] == 2.5
