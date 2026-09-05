import logging
import sys
import threading
import time

from api.app import create_app
from fastapi.testclient import TestClient
from pipeline.event_stream import CanonicalNormalizer
from pipeline.live_ingestion import (
    LOSS_EVENT_TYPE,
    CollectorHealth,
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


def test_backpressure_waits_for_the_consumer_instead_of_losing_events(tmp_path):
    """
    The point of backpressure: a consumer that is merely slow must cost latency,
    not evidence.

    The queue holds one event while forty arrive against a normalizer that
    sleeps, so the producer is forced to wait repeatedly. The
    backpressure_wait_count assertion is what makes this test mean anything --
    without it a run fast enough to never saturate would report zero drops and
    pass while proving nothing.
    """

    class SlowNormalizer(CanonicalNormalizer):
        def normalize(self, raw_event):
            time.sleep(0.002)
            return super().normalize(raw_event)

    store = SQLiteEventStore(str(tmp_path / "no_loss.db"))
    service = LiveIngestionService(
        [_event(timestamp=1000 + index, pid=index) for index in range(40)],
        store,
        queue_size=1,
        normalizer=SlowNormalizer(),
        backpressure_timeout_seconds=10.0,
    )

    health = service.run()

    assert health.status == "stopped"
    assert health.backpressure_wait_count > 0, "the queue never saturated; the test proves nothing"
    assert health.dropped_event_count == 0, "backpressure did not prevent loss"
    assert health.backpressure_wait_seconds > 0
    assert health.processed_count == 40
    assert store.count_events() == 40


def test_bounded_queue_counts_backpressure_drops(tmp_path, caplog):
    """
    Genuine saturation -- a consumer that is stuck rather than slow -- must lose
    events explicitly: counted, timestamped at both ends so ongoing loss is
    distinguishable from stale loss, and logged.

    backpressure_timeout_seconds=0 makes this deterministic. The previous
    version of this test raced the producer's wait budget against the blocked
    normalizer, so it could pass or fail on scheduling alone.
    """
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
        backpressure_timeout_seconds=0.0,
    )
    with caplog.at_level(logging.WARNING, logger="pipeline.live_ingestion"):
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

    health = service.health()
    assert health.dropped_event_count > 0
    assert health.status == "stopped"

    # Loss is attributable in time, not just in aggregate.
    assert health.first_drop_timestamp is not None
    assert health.last_drop_timestamp is not None
    assert health.first_drop_timestamp <= health.last_drop_timestamp

    # Every drop was preceded by an attempt to place the event.
    assert health.backpressure_wait_count >= health.dropped_event_count
    assert health.queue_capacity == 1
    assert health.queue_high_water_mark >= 1

    # The drop is visible to an operator reading logs, not only to a poller.
    drop_logs = [record for record in caplog.records if "telemetry event dropped" in record.getMessage()]
    assert drop_logs, "event loss was silent in the log"
    assert drop_logs[0].levelno == logging.WARNING
    assert "reason=queue_full" in drop_logs[0].getMessage()

    # ...and survives into the health record the API reads.
    persisted = store.read_collector_health()
    assert persisted["dropped_event_count"] == health.dropped_event_count
    assert persisted["first_drop_timestamp"] == health.first_drop_timestamp
    assert persisted["queue_capacity"] == 1
    # Queue occupancy is producer-owned rather than held under the health lock,
    # so it has to be folded into the persisted snapshot explicitly; without
    # that, the database reports an idle queue while the producer is blocking.
    assert persisted["queue_high_water_mark"] == health.queue_high_water_mark


def test_first_drop_timestamp_marks_when_loss_began(tmp_path):
    """
    first_drop_timestamp must stay pinned to the first loss while
    last_drop_timestamp tracks the most recent one. If the first were
    overwritten too, the pair would collapse into one number and an analyst
    could no longer see how long a gap in the evidence has been open.
    """
    service = LiveIngestionService([], SQLiteEventStore(str(tmp_path / "first_drop.db")))

    service._record_drop(0.0)
    began = service.health().first_drop_timestamp
    assert began is not None

    time.sleep(0.01)
    service._record_drop(0.0)
    service._record_drop(0.0)

    health = service.health()
    assert health.dropped_event_count == 3
    assert health.first_drop_timestamp == began, "the start of the loss window was overwritten"
    assert health.last_drop_timestamp > began, "the loss window never advanced"


def test_drop_logging_is_rate_limited_under_sustained_loss(tmp_path, caplog):
    """
    A line per lost event would compete for the CPU that is already behind and
    bury the first occurrence -- the one that records when loss began. One line
    per order of magnitude keeps the transitions visible; exact counts live in
    the health record.
    """
    store = SQLiteEventStore(str(tmp_path / "log_volume.db"))
    service = LiveIngestionService([], store, queue_size=1, backpressure_timeout_seconds=0.0)

    with caplog.at_level(logging.WARNING, logger="pipeline.live_ingestion"):
        for _ in range(120):
            service._record_drop(0.0)

    assert service.health().dropped_event_count == 120
    messages = [record.getMessage() for record in caplog.records if "telemetry event dropped" in record.getMessage()]
    assert len(messages) == 3, messages  # 1, 10, 100
    assert "dropped_event_count=1 " in messages[0]
    assert "dropped_event_count=100 " in messages[2]


def test_every_health_field_reaches_the_database(tmp_path):
    """
    write_collector_health used to name its columns inline, so a new
    CollectorHealth field was silently unpersisted: the supervisor would count
    something the API and dashboard could never show. This fails when a field is
    added without the migration that gives it a column.
    """
    store = SQLiteEventStore(str(tmp_path / "health_columns.db"))
    fields = set(CollectorHealth().to_dict())

    missing = fields - set(SQLiteEventStore.COLLECTOR_HEALTH_COLUMNS)
    assert not missing, f"CollectorHealth fields with no persisted column: {sorted(missing)}"

    store.write_collector_health(CollectorHealth(status="running").to_dict())
    persisted = store.read_collector_health()
    assert fields <= set(persisted), f"columns missing from collector_runtime: {sorted(fields - set(persisted))}"


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


def test_api_exposes_backpressure_and_event_loss_detail(tmp_path):
    """
    Loss has to be visible where an analyst looks. A count with no timing cannot
    distinguish a gap opening now from one that closed an hour ago.
    """
    store = SQLiteEventStore(str(tmp_path / "loss_api.db"))
    store.write_collector_health({
        "status": "running",
        "detail": "collector active",
        "dropped_event_count": 7,
        "queue_depth": 3,
        "queue_capacity": 1024,
        "queue_high_water_mark": 1024,
        "backpressure_wait_count": 19,
        "backpressure_wait_seconds": 4.5,
        "first_drop_timestamp": 1000.0,
        "last_drop_timestamp": 1200.0,
    })
    data = TestClient(create_app(store)).get("/api/status").json()

    assert data["dropped_event_count"] == 7
    assert data["collector_queue_depth"] == 3
    assert data["collector_queue_capacity"] == 1024
    assert data["collector_queue_high_water_mark"] == 1024
    assert data["collector_backpressure_wait_count"] == 19
    assert data["collector_backpressure_wait_seconds"] == 4.5
    assert data["first_drop_timestamp"] == 1000.0
    assert data["last_drop_timestamp"] == 1200.0


def test_api_reports_unknown_rather_than_zero_loss_without_a_collector(tmp_path):
    """
    Absent telemetry must not read as healthy. If these defaulted to 0 the
    dashboard would state that no events were dropped by a collector that has
    never reported at all.
    """
    data = TestClient(create_app(SQLiteEventStore(str(tmp_path / "silent.db")))).get("/api/status").json()

    assert data["dropped_event_count"] is None
    assert data["collector_queue_capacity"] is None
    assert data["first_drop_timestamp"] is None
    assert data["last_drop_timestamp"] is None
    assert data["kernel_lost_event_count"] is None
    assert data["first_kernel_loss_timestamp"] is None
    assert data["last_kernel_loss_timestamp"] is None


# --------------------------------------------------------------------------
# Kernel-side loss: samples the kernel discarded before this process saw them
# --------------------------------------------------------------------------


def _loss_record(lost=1, total=None, buffer_name="exec_events"):
    return {
        "event_type": LOSS_EVENT_TYPE,
        "timestamp": 1000.0,
        "lost_events": lost,
        "total_lost_events": lost if total is None else total,
        "buffer": buffer_name,
        "source": "telemetry_bcc",
        "version": "1.0",
    }


def test_kernel_loss_report_is_counted_not_stored_as_an_event(tmp_path):
    """
    The record describes the collector, not the machine. Storing it would add
    rows to the evidence table and shift `unique_event_types` for every window,
    and letting it reach the normalizer would count it as malformed -- reporting
    a decode failure where the truth is a kernel overrun.
    """
    store = SQLiteEventStore(str(tmp_path / "kernel_loss.db"))
    source = [_event(), _loss_record(lost=12), _event(timestamp=1001.0, pid=2)]

    health = LiveIngestionService(source, store).run()

    assert health.kernel_lost_event_count == 12
    assert health.malformed_count == 0
    assert health.dropped_event_count == 0
    assert health.processed_count == 2
    assert store.count_events() == 2


def test_kernel_loss_is_held_apart_from_queue_drops(tmp_path):
    """
    Two different failures with two different fixes: an overrun means the
    collector could not drain the kernel fast enough, a drop means this consumer
    could not keep up with the collector. One combined total would point at
    neither.
    """
    store = SQLiteEventStore(str(tmp_path / "loss_kinds.db"))
    service = LiveIngestionService([], store, queue_size=1, backpressure_timeout_seconds=0.0)

    service._record_drop(0.0)
    service._record_kernel_loss(_loss_record(lost=5))

    health = service.health()
    assert health.dropped_event_count == 1
    assert health.kernel_lost_event_count == 5


def test_kernel_loss_accumulates_and_timestamps_the_window(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "loss_window.db"))
    service = LiveIngestionService([], store)

    service._record_kernel_loss(_loss_record(lost=3, total=3))
    first = service.health().first_kernel_loss_timestamp
    time.sleep(0.01)
    service._record_kernel_loss(_loss_record(lost=4, total=7))

    health = service.health()
    assert health.kernel_lost_event_count == 7
    assert health.first_kernel_loss_timestamp == first
    assert health.last_kernel_loss_timestamp > first


def test_unreadable_kernel_loss_count_is_malformed_not_guessed(tmp_path):
    """
    A loss report we cannot parse tells us loss occurred but not how much.
    Assigning it a guessed magnitude would put a fabricated number in the
    evidence trail; counting it as malformed states exactly what happened.
    """
    store = SQLiteEventStore(str(tmp_path / "loss_bad.db"))
    service = LiveIngestionService([], store)

    for record in (
        {"event_type": LOSS_EVENT_TYPE},
        _loss_record(lost="many"),
        _loss_record(lost=None),
        _loss_record(lost=0),
        _loss_record(lost=-4),
    ):
        service._record_kernel_loss(record)

    health = service.health()
    assert health.kernel_lost_event_count == 0
    assert health.malformed_count == 5
    assert health.first_kernel_loss_timestamp is None


def test_kernel_loss_logging_reports_every_magnitude_of_a_batched_total(tmp_path, caplog):
    """
    Kernel loss arrives already batched, so the exact-power-of-ten test used for
    queue drops would never fire: a first report of 250 lost samples lands on no
    power of ten at all. The cadence is one line per magnitude *crossed*, which
    reports the onset and every escalation without a line per burst.
    """
    store = SQLiteEventStore(str(tmp_path / "loss_log.db"))
    service = LiveIngestionService([], store)

    with caplog.at_level(logging.WARNING, logger="pipeline.live_ingestion"):
        for _ in range(40):
            service._record_kernel_loss(_loss_record(lost=250))

    assert service.health().kernel_lost_event_count == 10000
    messages = [r.getMessage() for r in caplog.records if "lost in kernel" in r.getMessage()]
    # The running total gains a digit at 250, at 1000, and at 10000, and the 37
    # reports in between add nothing an operator needs a separate line for.
    assert len(messages) == 3, messages
    assert "kernel_lost_event_count=250 " in messages[0]
    assert "kernel_lost_event_count=1000 " in messages[1]
    assert "kernel_lost_event_count=10000 " in messages[2]
    assert "reason=perf_buffer_overrun" in messages[0]
    assert "buffer='exec_events'" in messages[0]
    # The increment travels alongside the total: one line saying 10000 without it
    # cannot distinguish a slow leak from a single catastrophic burst.
    assert "lost_events=250 " in messages[0]


def test_kernel_loss_logging_is_rate_limited_under_sustained_single_losses(tmp_path, caplog):
    store = SQLiteEventStore(str(tmp_path / "loss_log_single.db"))
    service = LiveIngestionService([], store)

    with caplog.at_level(logging.WARNING, logger="pipeline.live_ingestion"):
        for _ in range(120):
            service._record_kernel_loss(_loss_record(lost=1))

    messages = [r.getMessage() for r in caplog.records if "lost in kernel" in r.getMessage()]
    assert len(messages) == 3, messages  # 1, 10, 100


def test_kernel_loss_log_line_cannot_be_forged_by_a_collector(tmp_path, caplog):
    """
    The buffer name and the collector's own total come off the wire. Neither may
    inject a newline into the log and forge a second record.
    """
    store = SQLiteEventStore(str(tmp_path / "loss_inject.db"))
    service = LiveIngestionService([], store)

    with caplog.at_level(logging.WARNING, logger="pipeline.live_ingestion"):
        service._record_kernel_loss(
            _loss_record(lost=1, total="9\nWARNING forged line", buffer_name="a\nb")
        )

    messages = [r.getMessage() for r in caplog.records if "lost in kernel" in r.getMessage()]
    assert len(messages) == 1
    assert "\n" not in messages[0]
    assert "forged" not in messages[0]
    assert "collector_reported_total=unknown" in messages[0]


def test_kernel_loss_reaches_the_database_and_the_api(tmp_path):
    store = SQLiteEventStore(str(tmp_path / "loss_api_kernel.db"))
    LiveIngestionService([_event(), _loss_record(lost=9)], store).run()

    persisted = store.read_collector_health()
    assert persisted["kernel_lost_event_count"] == 9
    assert persisted["first_kernel_loss_timestamp"] is not None

    data = TestClient(create_app(store)).get("/api/status").json()
    assert data["kernel_lost_event_count"] == 9
    assert data["first_kernel_loss_timestamp"] == persisted["first_kernel_loss_timestamp"]
    assert data["last_kernel_loss_timestamp"] == persisted["last_kernel_loss_timestamp"]


def test_kernel_loss_report_is_intercepted_before_the_queue(tmp_path):
    """
    A loss report arrives precisely when things are congested. Routing it through
    the ingestion queue would make the record describing the loss the next thing
    to be dropped -- so the count would vanish exactly when it mattered. Here the
    queue holds one item and the timeout is zero, so anything that reaches the
    queue while it is full is lost.
    """
    store = SQLiteEventStore(str(tmp_path / "loss_bypass.db"))

    class BlockingNormalizer(CanonicalNormalizer):
        def normalize(self, raw_event):
            time.sleep(0.05)
            return super().normalize(raw_event)

    source = [_event(timestamp=1000.0 + index, pid=index + 1) for index in range(40)]
    source.append(_loss_record(lost=77))
    service = LiveIngestionService(
        source,
        store,
        normalizer=BlockingNormalizer(),
        queue_size=1,
        backpressure_timeout_seconds=0.0,
    )

    health = service.run()

    assert health.dropped_event_count > 0, "test did not saturate the queue; it proves nothing"
    assert health.kernel_lost_event_count == 77
