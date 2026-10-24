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