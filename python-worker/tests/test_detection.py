from datetime import datetime, timedelta, timezone

from app.detection import detect_repeated_auth_failures


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