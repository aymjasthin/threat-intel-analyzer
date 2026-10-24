from datetime import datetime, timedelta, timezone

from app.detection import detect_repeated_auth_failures
from app.detection import detect_high_request_rate
from app.detection import detect_large_payload_anomalies
from app.detection import detect_port_scanning


def make_event(event_id: int, event_type: str, timestamp: datetime) -> dict:
    return {
        "event_id": f"evt-{event_id}",
        "event_type": event_type,
        "source_ip": "192.168.1.50",
        "timestamp": timestamp.isoformat(),
    }


def test_detects_five_authentication_failures():
    start = datetime(2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc)

    events = [
        make_event(i, "auth_failure", start + timedelta(seconds=i * 5))
        for i in range(5)
    ]

    findings = detect_repeated_auth_failures(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AUTH-001"
    assert findings[0]["source_ip"] == "192.168.1.50"
    assert findings[0]["event_count"] == 5
    assert findings[0]["evidence"]["event_ids"] == [
        "evt-0",
        "evt-1",
        "evt-2",
        "evt-3",
        "evt-4",
    ]


def test_does_not_flag_four_authentication_failures():
    start = datetime(2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc)

    events = [
        make_event(i, "auth_failure", start + timedelta(seconds=i * 5))
        for i in range(4)
    ]

    findings = detect_repeated_auth_failures(events)

    assert findings == []


def test_ignores_other_event_types():
    start = datetime(2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc)

    events = [
        make_event(i, "auth_success", start + timedelta(seconds=i * 5))
        for i in range(5)
    ]

    findings = detect_repeated_auth_failures(events)

    assert findings == []

def test_does_not_flag_failures_spread_over_more_than_60_seconds():
    start = datetime(
        2026, 10, 24, 10, 0, 0,
        tzinfo=timezone.utc,
    )

    # Five failures, but the first and last are 80 seconds apart.
    failure_seconds = [0, 20, 40, 60, 80]

    events = [
        make_event(
            i,
            "auth_failure",
            start + timedelta(seconds=second),
        )
        for i, second in enumerate(failure_seconds)
    ]

    findings = detect_repeated_auth_failures(events)

    assert findings == []

def test_detects_failures_arriving_out_of_order():
    start = datetime(
        2026, 10, 24, 10, 0, 0,
        tzinfo=timezone.utc,
    )

    arrival_seconds = [40, 5, 30, 15, 20]

    events = [
        make_event(
            i,
            "auth_failure",
            start + timedelta(seconds=second),
        )
        for i, second in enumerate(arrival_seconds)
    ]

    findings = detect_repeated_auth_failures(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AUTH-001"
    assert findings[0]["event_count"] == 5
    assert findings[0]["evidence"]["event_ids"] == [
        "evt-1",
        "evt-3",
        "evt-4",
        "evt-2",
        "evt-0",
    ]

def test_detects_five_failures_within_exactly_60_seconds():
    start = datetime(
        2026, 10, 24, 10, 0, 0,
        tzinfo=timezone.utc,
    )

    # The first and last failures are exactly 60 seconds apart.
    failure_seconds = [0, 15, 30, 45, 60]

    events = [
        make_event(
            i,
            "auth_failure",
            start + timedelta(seconds=second),
        )
        for i, second in enumerate(failure_seconds)
    ]

    findings = detect_repeated_auth_failures(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AUTH-001"
    assert findings[0]["event_count"] == 5

def test_reanalyzing_same_events_generates_new_finding_id():
    start = datetime(
        2026, 10, 24, 10, 0, 0,
        tzinfo=timezone.utc,
    )

    events = [
        make_event(
            i,
            "auth_failure",
            start + timedelta(seconds=i * 5),
        )
        for i in range(5)
    ]

    first_findings = detect_repeated_auth_failures(events)
    second_findings = detect_repeated_auth_failures(events)

    assert len(first_findings) == 1
    assert len(second_findings) == 1

    assert (
        first_findings[0]["finding_id"]
        != second_findings[0]["finding_id"]
    )

def test_ignores_auth_failure_with_invalid_timestamp():
    events = [
        {
            "event_id": "evt-invalid",
            "event_type": "auth_failure",
            "source_ip": "192.168.1.50",
            "timestamp": "not-a-timestamp",
        }
    ]

    findings = detect_repeated_auth_failures(events)

    assert findings == []

def test_ignores_auth_failure_with_non_string_timestamp():
    events = [
        {
            "event_id": "evt-invalid-type",
            "event_type": "auth_failure",
            "source_ip": "192.168.1.50",
            "timestamp": 12345,
        }
    ]

    findings = detect_repeated_auth_failures(events)

    assert findings == []

def test_detects_multiple_source_ips_independently():
    events = []

    for source_ip, failure_count in [
        ("192.168.1.10", 5),
        ("192.168.1.20", 3),
        ("192.168.1.30", 6),
    ]:
        for index in range(failure_count):
            events.append({
                "event_id": f"{source_ip}-{index}",
                "event_type": "auth_failure",
                "source_ip": source_ip,
                "timestamp": f"2026-10-24T10:00:{index:02d}+00:00",
            })

    findings = detect_repeated_auth_failures(events)

    assert len(findings) == 2

    findings_by_ip = {
        finding["source_ip"]: finding
        for finding in findings
    }

    assert findings_by_ip["192.168.1.10"]["event_count"] == 5
    assert findings_by_ip["192.168.1.30"]["event_count"] == 5

    assert "192.168.1.20" not in findings_by_ip

def test_detects_rolling_window_after_old_event_expires():
    seconds = [0, 50, 55, 60, 65, 70]

    events = [
        {
            "event_id": f"evt-{index}",
            "event_type": "auth_failure",
            "source_ip": "192.168.1.50",
            "timestamp": (
                datetime(2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc)
                + timedelta(seconds=second)
            ).isoformat(),
        }
        for index, second in enumerate(seconds)
    ]

    findings = detect_repeated_auth_failures(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding["event_count"] == 5
    assert finding["evidence"]["event_ids"] == [
        "evt-1",
        "evt-2",
        "evt-3",
        "evt-4",
        "evt-5",
    ]

def test_detects_more_than_100_requests_within_60_seconds():
    events = [
        {
            "event_id": f"req-{index}",
            "event_type": "request",
            "source_ip": "192.168.1.100",
            "timestamp": (
                datetime(2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc)
                + timedelta(milliseconds=index * 500)
            ).isoformat(),
        }
        for index in range(101)
    ]

    findings = detect_high_request_rate(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding["rule_id"] == "NET-001"
    assert finding["source_ip"] == "192.168.1.100"
    assert finding["event_count"] == 101


def test_does_not_flag_exactly_100_requests():
    events = [
        {
            "event_id": f"req-{index}",
            "event_type": "request",
            "source_ip": "192.168.1.100",
            "timestamp": (
                datetime(2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc)
                + timedelta(milliseconds=index * 500)
            ).isoformat(),
        }
        for index in range(100)
    ]

    findings = detect_high_request_rate(events)

    assert findings == []

def test_does_not_flag_requests_spread_over_more_than_60_seconds():
    events = [
        {
            "event_id": f"req-{index}",
            "event_type": "request",
            "source_ip": "192.168.1.100",
            "timestamp": (
                datetime(2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc)
                + timedelta(seconds=index * 2)
            ).isoformat(),
        }
        for index in range(101)
    ]

    findings = detect_high_request_rate(events)

    assert findings == []

def test_detects_unusually_large_payload():
    events = []

    for index in range(20):
        events.append({
            "event_id": f"req-{index}",
            "event_type": "request",
            "source_ip": "192.168.1.50",
            "timestamp": "2026-10-24T10:00:00+00:00",
            "payload_size": 400 + (index % 5) * 10,
        })

    events.append({
        "event_id": "req-anomaly",
        "event_type": "request",
        "source_ip": "192.168.1.50",
        "timestamp": "2026-10-24T10:00:01+00:00",
        "payload_size": 50000,
    })

    findings = detect_large_payload_anomalies(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding["rule_id"] == "NET-002"
    assert finding["detection_type"] == "anomaly_based"
    assert finding["evidence"]["event_ids"] == ["req-anomaly"]

def test_does_not_flag_identical_payload_sizes():
    events = [
        {
            "event_id": f"req-{index}",
            "event_type": "request",
            "source_ip": "192.168.1.50",
            "timestamp": "2026-10-24T10:00:00+00:00",
            "payload_size": 400,
        }
        for index in range(20)
    ]

    findings = detect_large_payload_anomalies(events)

    assert findings == []

def test_does_not_flag_single_payload():
    events = [
        {
            "event_id": "req-1",
            "event_type": "request",
            "source_ip": "192.168.1.50",
            "timestamp": "2026-10-24T10:00:00+00:00",
            "payload_size": 50000,
        }
    ]

    findings = detect_large_payload_anomalies(events)

    assert findings == []

def test_large_payload_detector_ignores_invalid_sizes():
    events = [
        {
            "event_id": "invalid-negative",
            "event_type": "request",
            "payload_size": -100,
        },
        {
            "event_id": "invalid-string",
            "event_type": "request",
            "payload_size": "50000",
        },
        {
            "event_id": "invalid-boolean",
            "event_type": "request",
            "payload_size": True,
        },
        {
            "event_id": "invalid-missing",
            "event_type": "request",
        },
    ]

    findings = detect_large_payload_anomalies(events)

    assert findings == []

def test_detects_port_scanning():
    events = []

    for index in range(20):
        events.append({
            "event_id": f"conn-{index}",
            "event_type": "connection",
            "source_ip": "192.168.1.50",
            "timestamp": "2026-10-24T10:00:00+00:00",
            "destination_port": 1000 + index,
        })

    findings = detect_port_scanning(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding["rule_id"] == "NET-003"
    assert finding["detection_type"] == "rule_based"
    assert finding["evidence"]["distinct_port_count"] == 20

def test_port_scanning_ignores_duplicate_ports():
    events = []

    for index in range(20):
        events.append({
            "event_id": f"conn-{index}",
            "event_type": "connection",
            "source_ip": "192.168.1.50",
            "timestamp": "2026-10-24T10:00:00+00:00",
            "destination_port": 443,
        })

    findings = detect_port_scanning(events)

    assert findings == []

def test_port_scanning_respects_time_window():
    start_time = datetime(
        2026, 10, 24, 10, 0, 0,
        tzinfo=timezone.utc,
    )

    events = []

    for index in range(20):
        events.append({
            "event_id": f"conn-{index}",
            "event_type": "connection",
            "source_ip": "192.168.1.50",
            "timestamp": (
                start_time + timedelta(seconds=index * 10)
            ).isoformat(),
            "destination_port": 1000 + index,
        })

    findings = detect_port_scanning(events)

    assert findings == []

def test_port_scanning_handles_out_of_order_events():
    start_time = datetime(
        2026, 10, 24, 10, 0, 0,
        tzinfo=timezone.utc,
    )

    events = []

    for index in range(20):
        events.append({
            "event_id": f"conn-{index}",
            "event_type": "connection",
            "source_ip": "192.168.1.50",
            "timestamp": (
                start_time + timedelta(seconds=index * 2)
            ).isoformat(),
            "destination_port": 1000 + index,
        })

    # Simulate events arriving in reverse chronological order.
    events.reverse()

    findings = detect_port_scanning(events)

    assert len(findings) == 1

    finding = findings[0]

    assert finding["rule_id"] == "NET-003"
    assert finding["evidence"]["distinct_port_count"] == 20
    assert finding["first_seen"] == start_time.isoformat()
    assert finding["last_seen"] == (
        start_time + timedelta(seconds=38)
    ).isoformat()

def test_port_scanning_handles_multiple_source_ips():
    events = []

    for index in range(20):
        events.append({
            "event_id": f"ip1-{index}",
            "event_type": "connection",
            "source_ip": "192.168.1.50",
            "timestamp": "2026-10-24T10:00:00+00:00",
            "destination_port": 1000 + index,
        })

    for index in range(20):
        events.append({
            "event_id": f"ip2-{index}",
            "event_type": "connection",
            "source_ip": "192.168.1.100",
            "timestamp": "2026-10-24T10:00:00+00:00",
            "destination_port": 2000 + index,
        })

    findings = detect_port_scanning(events)

    assert len(findings) == 2

    source_ips = {
        finding["source_ip"]
        for finding in findings
    }

    assert source_ips == {
        "192.168.1.50",
        "192.168.1.100",
    }

    for finding in findings:
        assert finding["rule_id"] == "NET-003"
        assert finding["evidence"]["distinct_port_count"] == 20