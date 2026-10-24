# Detection Rules

This document defines the initial detection rules for
Threat Intel Analyzer.

Thresholds are initial development defaults and must be
validated against representative data before production use.

## AUTH-001: Repeated Authentication Failures

- Detection method: Rule-based
- Initial severity: Medium
- Grouping: Source IP
- Window: Rolling 60 seconds
- Threshold: At least 5 authentication failures

Generate a finding when the threshold is reached.

Evidence:
- Source IP
- Failure count
- Time window
- First and last observed timestamps

Only events that explicitly represent authentication failures
may contribute to this rule.

## NET-001: High Request Rate

- Detection method: Rule-based
- Initial severity: Medium
- Grouping: Source IP
- Window: Rolling 60 seconds
- Threshold: More than 100 requests

Generate a finding when the threshold is exceeded.

Evidence:
- Source IP
- Request count
- Time window
- First and last observed timestamps

Request events must be distinguished from connection events.

## NET-002: Unusually Large Payload

- Detection method: Anomaly-based
- Severity: Determined by detection policy and context
- Initial method: Statistical analysis

Identify payload sizes that differ significantly from an
appropriate baseline.

Evidence:
- Observed payload size
- Baseline measurements
- Anomaly score
- Analysis method

An anomaly score is not a probability of malicious activity.

## NET-003: Connection Attempts Across Many Ports

- Detection method: Rule-based
- Initial severity: Medium
- Grouping: Source IP
- Window: Rolling 60 seconds
- Threshold: At least 20 distinct destination ports

Generate a finding when the threshold is reached.

Evidence:
- Source IP
- Distinct destination port count
- Time window
- First and last observed timestamps

This rule requires destination-port information in the event
contract.

## TI-001: Threat Intelligence Match

- Detection method: Threat intelligence
- Severity: Based on indicator context and detection policy

Generate a finding when an observed indicator matches a
configured threat-intelligence indicator.

Evidence:
- Matched indicator
- Indicator type
- Intelligence source
- Retrieval timestamp
- Expiration or freshness information, when available

A match does not independently prove malicious activity.

## General Requirements

- All rules must have stable identifiers.
- Findings must conform to finding.schema.json.
- Detection thresholds must be configurable where practical.
- Invalid events must not silently enter detection calculations.
- Findings must include enough evidence to explain the detection.
- Repeated processing must not create uncontrolled duplicate findings.
- Detection behavior must be covered by automated tests.