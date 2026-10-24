from collections import defaultdict
from datetime import datetime, timedelta, timezone
from uuid import uuid4


AUTH_FAILURE_THRESHOLD = 5
AUTH_FAILURE_WINDOW_SECONDS = 60


def detect_repeated_auth_failures(events: list[dict]) -> list[dict]:
    """
    Detect source IP addresses with at least five authentication
    failures within a rolling 60-second window.
    """

    failures_by_ip = defaultdict(list)

    for event in events:
        if event.get("event_type") != "auth_failure":
            continue

        source_ip = event.get("source_ip")
        timestamp = event.get("timestamp")
        event_id = event.get("event_id")

        if not source_ip or not timestamp or not event_id:
            continue

        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

        if timestamp.tzinfo is None:
            continue

        timestamp = timestamp.astimezone(timezone.utc)

        failures_by_ip[str(source_ip)].append({
            "event_id": event_id,
            "timestamp": timestamp,
        })

    findings = []

    for source_ip, failures in failures_by_ip.items():
        failures.sort(key=lambda failure: failure["timestamp"])
        left = 0

        for right, current_failure in enumerate(failures):
            current_time = current_failure["timestamp"]

            while (
                current_time - failures[left]["timestamp"]
                > timedelta(seconds=AUTH_FAILURE_WINDOW_SECONDS)
            ):
                left += 1

            failure_count = right - left + 1

            if failure_count >= AUTH_FAILURE_THRESHOLD:
                window_failures = failures[left:right + 1]
                window_timestamps = [
                    failure["timestamp"]
                    for failure in window_failures
                ]

                event_ids = [
                    failure["event_id"]
                    for failure in window_failures
                ]

                findings.append({
                    "finding_id": str(uuid4()),
                    "title": "Repeated Authentication Failures",
                    "severity": "medium",
                    "detection_type": "rule_based",
                    "rule_id": "AUTH-001",
                    "description": (
                        f"{failure_count} authentication failures from "
                        f"{source_ip} occurred within "
                        f"{AUTH_FAILURE_WINDOW_SECONDS} seconds."
                    ),
                    "source_ip": source_ip,
                    "first_seen": window_timestamps[0].isoformat(),
                    "last_seen": window_timestamps[-1].isoformat(),
                    "event_count": failure_count,
                    "evidence": {
                        "source_ip": source_ip,
                        "failure_count": failure_count,
                        "window_seconds": AUTH_FAILURE_WINDOW_SECONDS,
                        "event_ids": event_ids,
                    },
                })

                # Report only the first qualifying window for this IP.
                break

    return findings