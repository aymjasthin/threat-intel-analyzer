from fastapi.testclient import TestClient

from datetime import datetime, timedelta, timezone

from app.main import app


client = TestClient(app)


def make_event(event_id: int, event_type: str, second: int) -> dict:
    return {
        "event_id": f"evt-{event_id}",
        "timestamp": f"2026-10-24T10:00:{second:02d}Z",
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.10",
        "protocol": "TCP",
        "event_type": event_type,
        "payload_size": 120,
        "destination_port": 443,
    }


def test_analyze_detects_repeated_authentication_failures():
    events = [
        make_event(i, "auth_failure", i * 5)
        for i in range(5)
    ]

    response = client.post("/analyze", json={"events": events})

    assert response.status_code == 200

    body = response.json()

    assert body["events_received"] == 5
    assert body["findings_count"] == 1
    assert body["findings"][0]["rule_id"] == "AUTH-001"
    assert body["findings"][0]["source_ip"] == "192.168.1.50"


def test_analyze_does_not_flag_four_authentication_failures():
    events = [
        make_event(i, "auth_failure", i * 5)
        for i in range(4)
    ]

    response = client.post("/analyze", json={"events": events})

    assert response.status_code == 200

    body = response.json()

    assert body["events_received"] == 4
    assert body["findings_count"] == 0
    assert body["findings"] == []


def test_analyze_rejects_invalid_event():
    invalid_event = make_event(1, "auth_failure", 0)
    invalid_event["source_ip"] = "not-an-ip"

    response = client.post(
        "/analyze",
        json={"events": [invalid_event]},
    )

    assert response.status_code == 422

def test_analyze_detects_high_request_rate():
    start_time = datetime(
        2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc
    )

    events = [
        {
            "event_id": f"req-{index}",
            "timestamp": (
                start_time + timedelta(milliseconds=index * 500)
            ).isoformat(),
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.1",
            "protocol": "TCP",
            "event_type": "request",
            "payload_size": 400,
            "destination_port": 80,
        }
        for index in range(101)
    ]

    response = client.post(
        "/analyze",
        json={"events": events},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["events_received"] == 101
    assert data["findings_count"] == 1

    finding = data["findings"][0]

    assert finding["rule_id"] == "NET-001"
    assert finding["source_ip"] == "192.168.1.100"
    assert finding["event_count"] == 101

def test_analyze_detects_multiple_rules():
    start_time = datetime(
        2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc
    )

    events = []

    # Generate 5 authentication failures.
    for index in range(5):
        events.append({
            "event_id": f"auth-{index}",
            "timestamp": (
                start_time + timedelta(seconds=index * 5)
            ).isoformat(),
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.1",
            "protocol": "TCP",
            "event_type": "auth_failure",
            "payload_size": 200,
            "destination_port": 22,
        })

    # Generate 101 network requests.
    for index in range(101):
        events.append({
            "event_id": f"req-{index}",
            "timestamp": (
                start_time + timedelta(milliseconds=index * 500)
            ).isoformat(),
            "source_ip": "192.168.1.100",
            "destination_ip": "192.168.1.1",
            "protocol": "TCP",
            "event_type": "request",
            "payload_size": 400,
            "destination_port": 80,
        })

    response = client.post(
        "/analyze",
        json={"events": events},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["events_received"] == 106
    assert data["findings_count"] == 2

    rule_ids = {
        finding["rule_id"]
        for finding in data["findings"]
    }

    assert rule_ids == {"AUTH-001", "NET-001"}

def test_analyze_detects_large_payload_anomaly():
    events = []

    for index in range(20):
        events.append({
            "event_id": f"req-{index}",
            "event_type": "request",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.1",
            "protocol": "TCP",
            "timestamp": "2026-10-24T10:00:00+00:00",
            "payload_size": 400 + (index % 5) * 10,
            "destination_port": 443,
        })

    events.append({
        "event_id": "req-anomaly",
        "event_type": "request",
        "source_ip": "192.168.1.50",
        "destination_ip": "192.168.1.1",
        "protocol": "TCP",
        "timestamp": "2026-10-24T10:00:01+00:00",
        "payload_size": 50000,
        "destination_port": 443,
    })

    response = client.post("/analyze", json={"events": events})

    assert response.status_code == 200

    data = response.json()

    assert data["events_received"] == 21
    assert data["findings_count"] == 1

    finding = data["findings"][0]

    assert finding["rule_id"] == "NET-002"
    assert finding["detection_type"] == "anomaly_based"
    assert finding["evidence"]["event_ids"] == ["req-anomaly"]

def test_analyze_detects_port_scanning():
    events = []

    for index in range(20):
        events.append({
            "event_id": f"conn-{index}",
            "event_type": "connection",
            "source_ip": "192.168.1.50",
            "destination_ip": "192.168.1.1",
            "protocol": "TCP",
            "timestamp": "2026-10-24T10:00:00+00:00",
            "payload_size": 400,
            "destination_port": 1000 + index,
        })

    response = client.post("/analyze", json={"events": events})

    assert response.status_code == 200

    data = response.json()

    assert data["events_received"] == 20
    assert data["findings_count"] == 1

    finding = data["findings"][0]

    assert finding["rule_id"] == "NET-003"
    assert finding["detection_type"] == "rule_based"
    assert finding["severity"] == "medium"

    assert finding["evidence"]["distinct_port_count"] == 20
    assert len(finding["evidence"]["destination_ports"]) == 20
    assert len(finding["evidence"]["event_ids"]) == 20