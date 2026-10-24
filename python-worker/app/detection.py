from collections import defaultdict
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import statistics


AUTH_FAILURE_THRESHOLD = 5
AUTH_FAILURE_WINDOW_SECONDS = 60

HIGH_REQUEST_THRESHOLD = 100
HIGH_REQUEST_WINDOW_SECONDS = 60

ANOMALY_Z_SCORE_THRESHOLD = 3.0

PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW_SECONDS = 60


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
            try:
                timestamp = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )
            except ValueError:
                continue
        elif not isinstance(timestamp, datetime):
            continue

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

def detect_high_request_rate(events: list[dict]) -> list[dict]:
    """
    Detect source IP addresses generating more than
    100 requests within a rolling 60-second window.
    """

    requests_by_ip = defaultdict(list)

    for event in events:
        if event.get("event_type") != "request":
            continue

        source_ip = event.get("source_ip")
        timestamp = event.get("timestamp")
        event_id = event.get("event_id")

        if not source_ip or not timestamp or not event_id:
            continue

        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )
            except ValueError:
                continue
        elif not isinstance(timestamp, datetime):
            continue

        if timestamp.tzinfo is None:
            continue

        timestamp = timestamp.astimezone(timezone.utc)

        requests_by_ip[str(source_ip)].append({
            "event_id": event_id,
            "timestamp": timestamp,
        })

    findings = []

    for source_ip, requests in requests_by_ip.items():
        requests.sort(key=lambda request: request["timestamp"])

        left = 0

        for right, current_request in enumerate(requests):
            current_time = current_request["timestamp"]

            while (
                current_time - requests[left]["timestamp"]
                > timedelta(seconds=HIGH_REQUEST_WINDOW_SECONDS)
            ):
                left += 1

            request_count = right - left + 1

            if request_count > HIGH_REQUEST_THRESHOLD:
                window_requests = requests[left:right + 1]

                findings.append({
                    "finding_id": str(uuid4()),
                    "title": "High Request Rate",
                    "severity": "medium",
                    "detection_type": "rule_based",
                    "rule_id": "NET-001",
                    "description": (
                        f"{request_count} requests from {source_ip} "
                        f"occurred within "
                        f"{HIGH_REQUEST_WINDOW_SECONDS} seconds."
                    ),
                    "source_ip": source_ip,
                    "first_seen": window_requests[0]["timestamp"].isoformat(),
                    "last_seen": window_requests[-1]["timestamp"].isoformat(),
                    "event_count": request_count,
                    "evidence": {
                        "source_ip": source_ip,
                        "request_count": request_count,
                        "window_seconds": HIGH_REQUEST_WINDOW_SECONDS,
                        "event_ids": [
                            request["event_id"]
                            for request in window_requests
                        ],
                    },
                })

                break

    return findings

def detect_large_payload_anomalies(events: list[dict]) -> list[dict]:
    """
    Detect unusually large payloads using statistical analysis.
    """

    payload_events = []

    for event in events:
        if event.get("event_type") != "request":
            continue

        payload_size = event.get("payload_size")

        if (
            not isinstance(payload_size, int)
            or isinstance(payload_size, bool)
            or payload_size < 0
        ):
            continue

        payload_events.append(event)

    if len(payload_events) < 2:
        return []

    payload_sizes = [
        event["payload_size"]
        for event in payload_events
    ]

    mean = statistics.mean(payload_sizes)
    standard_deviation = statistics.pstdev(payload_sizes)

    if standard_deviation == 0:
        return []

    findings = []

    for event in payload_events:
        payload_size = event["payload_size"]

        z_score = (
            (payload_size - mean) / standard_deviation
        )

        print(
            f"Payload: {payload_size}, "
            f"Mean: {mean:.2f}, "
            f"Std Dev: {standard_deviation:.2f}, "
            f"Z-score: {z_score:.2f}"
        )

        if z_score > ANOMALY_Z_SCORE_THRESHOLD:
            findings.append({
                "finding_id": str(uuid4()),
                "title": "Unusually Large Payload",
                "severity": "medium",
                "detection_type": "anomaly_based",
                "rule_id": "NET-002",
                "description": (
                    f"Payload size of {payload_size} bytes "
                    f"has a Z-score of {z_score:.2f}."
                ),
                "source_ip": event.get("source_ip"),
                "first_seen": event["timestamp"],
                "last_seen": event["timestamp"],
                "event_count": 1,
                "evidence": {
                    "source_ip": event.get("source_ip"),
                    "payload_size": payload_size,
                    "mean_payload_size": mean,
                    "standard_deviation": standard_deviation,
                    "z_score": z_score,
                    "threshold": ANOMALY_Z_SCORE_THRESHOLD,
                    "event_ids": [event["event_id"]],
                },
            })

    return findings

def detect_port_scanning(events: list[dict]) -> list[dict]:
    """
    Detect source IPs contacting at least 20 distinct
    destination ports within a rolling 60-second window.
    """

    connections_by_ip = defaultdict(list)

    # Step 1: Collect valid connection events.
    for event in events:
        if event.get("event_type") != "connection":
            continue

        source_ip = event.get("source_ip")
        timestamp = event.get("timestamp")
        event_id = event.get("event_id")
        destination_port = event.get("destination_port")

        if not source_ip or not timestamp or not event_id:
            continue

        if (
            not isinstance(destination_port, int)
            or isinstance(destination_port, bool)
            or not 1 <= destination_port <= 65535
        ):
            continue

        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )
            except ValueError:
                continue
        elif not isinstance(timestamp, datetime):
            continue

        if timestamp.tzinfo is None:
            continue

        timestamp = timestamp.astimezone(timezone.utc)

        connections_by_ip[str(source_ip)].append({
            "event_id": event_id,
            "timestamp": timestamp,
            "destination_port": destination_port,
        })

    findings = []

    # Step 2: Analyze each source IP independently.
    for source_ip, connections in connections_by_ip.items():
        connections.sort(key=lambda connection: connection["timestamp"])

        left = 0

        for right, current_connection in enumerate(connections):
            current_time = current_connection["timestamp"]

            # Step 3: Maintain a rolling 60-second window.
            while (
                current_time - connections[left]["timestamp"]
                > timedelta(seconds=PORT_SCAN_WINDOW_SECONDS)
            ):
                left += 1

            window_connections = connections[left:right + 1]

            # Step 4: Count distinct destination ports.
            distinct_ports = {
                connection["destination_port"]
                for connection in window_connections
            }

            if len(distinct_ports) >= PORT_SCAN_THRESHOLD:
                findings.append({
                    "finding_id": str(uuid4()),
                    "title": "Potential Port Scan",
                    "severity": "medium",
                    "detection_type": "rule_based",
                    "rule_id": "NET-003",
                    "description": (
                        f"{source_ip} contacted "
                        f"{len(distinct_ports)} distinct ports within "
                        f"{PORT_SCAN_WINDOW_SECONDS} seconds."
                    ),
                    "source_ip": source_ip,
                    "first_seen": window_connections[0]["timestamp"].isoformat(),
                    "last_seen": window_connections[-1]["timestamp"].isoformat(),
                    "event_count": len(window_connections),
                    "evidence": {
                        "source_ip": source_ip,
                        "distinct_port_count": len(distinct_ports),
                        "destination_ports": sorted(distinct_ports),
                        "window_seconds": PORT_SCAN_WINDOW_SECONDS,
                        "event_ids": [
                            connection["event_id"]
                            for connection in window_connections
                        ],
                    },
                })

                # Report only the first qualifying window per IP.
                break

    return findings

def detect_threat_intelligence_matches(
    events: list[dict],
    threat_intel_ips: set[str],
) -> list[dict]:
    """
    Detect events whose source IP appears
    in the provided threat intelligence list.
    """

    findings = []

    for event in events:
        source_ip = event.get("source_ip")
        event_id = event.get("event_id")
        timestamp = event.get("timestamp")

        # Skip events missing essential information.
        if not source_ip or not event_id or not timestamp:
            continue

        # Check whether the source IP is in our intelligence list.
        if str(source_ip) not in threat_intel_ips:
            continue

        findings.append({
            "finding_id": str(uuid4()),
            "title": "Threat Intelligence IP Match",
            "severity": "medium",
            "detection_type": "threat_intel",
            "rule_id": "TI-001",
            "description": (
                f"Source IP {source_ip} matches an entry "
                "in the threat intelligence dataset."
            ),
            "source_ip": str(source_ip),
            "first_seen": timestamp,
            "last_seen": timestamp,
            "event_count": 1,
            "evidence": {
                "source_ip": str(source_ip),
                "matched_ip": str(source_ip),
                "event_ids": [event_id],
            },
        })

    return findings