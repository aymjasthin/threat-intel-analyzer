from datetime import datetime
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

from app.detection import (
    detect_repeated_auth_failures,
    detect_high_request_rate,
    detect_large_payload_anomalies,
    detect_port_scanning,
)


app = FastAPI(
    title="Threat Intel Analyzer",
    description="Python worker for security event analysis",
    version="0.1.0",
)


class SecurityEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1)
    timestamp: datetime
    source_ip: IPvAnyAddress | None
    destination_ip: IPvAnyAddress | None
    protocol: Literal["TCP", "UDP", "ICMP"] | None
    event_type: Literal[
        "connection",
        "request",
        "auth_success",
        "auth_failure",
        "dns_query",
    ]
    payload_size: int | None = Field(default=None, ge=0)
    destination_port: int | None = Field(default=None, ge=1, le=65535)


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    events: list[SecurityEvent] = Field(min_length=1)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "python-worker",
    }


@app.post("/events/validate")
def validate_event(event: SecurityEvent):
    return {
        "status": "accepted",
        "event_id": event.event_id,
        "event_type": event.event_type,
    }


@app.post("/analyze")
def analyze_events(request: AnalyzeRequest):
    events = [event.model_dump(mode="json") for event in request.events]

    auth_findings = detect_repeated_auth_failures(events)
    request_findings = detect_high_request_rate(events)
    payload_findings = detect_large_payload_anomalies(events)
    port_scan_findings = detect_port_scanning(events)

    findings = (
        auth_findings
        + request_findings
        + payload_findings
        + port_scan_findings
    )

    return {
        "events_received": len(events),
        "findings_count": len(findings),
        "findings": findings,
    }