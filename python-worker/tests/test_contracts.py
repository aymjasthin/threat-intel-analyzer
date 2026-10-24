import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from app.detection import detect_repeated_auth_failures


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