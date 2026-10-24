import json
from pathlib import Path

from datetime import datetime, timedelta, timezone

from jsonschema import Draft202012Validator, FormatChecker

from app.detection import detect_repeated_auth_failures
from app.detection import detect_high_request_rate
from app.detection import detect_large_payload_anomalies
from app.detection import detect_port_scanning

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "contracts" / "finding.schema.json"


def test_auth_failure_finding_matches_shared_schema():
    with SCHEMA_PATH.open(encoding="utf-8") as schema_file:
        schema = json.load(schema_file)

    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    events = [
        {
            "event_id": f"evt-{i}",
            "timestamp": f"2026-10-24T10:00:{i * 5:02d}+00:00",
            "source_ip": "192.168.1.50",
            "event_type": "auth_failure",
        }
        for i in range(5)
    ]

    findings = detect_repeated_auth_failures(events)

    assert len(findings) == 1

    errors = list(validator.iter_errors(findings[0]))

    assert errors == [], (
        "Finding violates the shared JSON Schema:\n"
        + "\n".join(error.message for error in errors)
    )

def test_finding_schema_rejects_empty_event_ids():
    with SCHEMA_PATH.open(encoding="utf-8") as schema_file:
        schema = json.load(schema_file)

    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    invalid_finding = {
        "finding_id": "finding-test",
        "title": "Repeated Authentication Failures",
        "severity": "medium",
        "detection_type": "rule_based",
        "rule_id": "AUTH-001",
        "description": "Five authentication failures detected.",
        "source_ip": "192.168.1.50",
        "first_seen": "2026-10-24T10:00:00+00:00",
        "last_seen": "2026-10-24T10:00:20+00:00",
        "event_count": 5,
        "evidence": {
            "source_ip": "192.168.1.50",
            "failure_count": 5,
            "window_seconds": 60,
            "event_ids": [],
        },
    }

    errors = list(validator.iter_errors(invalid_finding))

    assert any(
        error.validator == "minItems"
        for error in errors
    ), "The schema should reject an empty event_ids array."

def test_high_request_rate_finding_matches_shared_schema():
    start_time = datetime(
        2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc
    )

    events = [
        {
            "event_id": f"req-{index}",
            "event_type": "request",
            "source_ip": "192.168.1.100",
            "timestamp": (
                start_time + timedelta(milliseconds=index * 500)
            ).isoformat(),
        }
        for index in range(101)
    ]

    findings = detect_high_request_rate(events)

    assert len(findings) == 1

    with SCHEMA_PATH.open() as file:
        schema = json.load(file)

    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    errors = list(validator.iter_errors(findings[0]))

    assert errors == []

def test_large_payload_finding_matches_schema():
    events = [
        {
            "event_id": f"req-{index}",
            "event_type": "request",
            "source_ip": "192.168.1.50",
            "timestamp": "2026-10-24T10:00:00+00:00",
            "payload_size": 400 + (index % 5) * 10,
        }
        for index in range(20)
    ]

    events.append({
        "event_id": "req-anomaly",
        "event_type": "request",
        "source_ip": "192.168.1.50",
        "timestamp": "2026-10-24T10:00:01+00:00",
        "payload_size": 50000,
    })

    findings = detect_large_payload_anomalies(events)

    assert len(findings) == 1

    with SCHEMA_PATH.open(encoding="utf-8") as schema_file:
        schema = json.load(schema_file)

    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    errors = list(validator.iter_errors(findings[0]))

    assert errors == [], (
        "NET-002 finding violates the shared JSON Schema:\n"
        + "\n".join(error.message for error in errors)
    )

def test_port_scanning_finding_matches_schema():
    events = [
        {
            "event_id": f"conn-{index}",
            "event_type": "connection",
            "source_ip": "192.168.1.50",
            "timestamp": "2026-10-24T10:00:00+00:00",
            "destination_port": 1000 + index,
        }
        for index in range(20)
    ]

    findings = detect_port_scanning(events)

    assert len(findings) == 1

    with SCHEMA_PATH.open(encoding="utf-8") as schema_file:
        schema = json.load(schema_file)

    validator = Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )

    errors = list(validator.iter_errors(findings[0]))

    assert errors == [], (
        "NET-003 finding violates the shared JSON Schema:\n"
        + "\n".join(error.message for error in errors)
    )