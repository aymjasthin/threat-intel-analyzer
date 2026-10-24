from fastapi.testclient import TestClient

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