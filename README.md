cat > README.md <<'EOF'
# Threat Intel Analyzer

A modular cybersecurity platform for network event analysis,
anomaly detection, and threat intelligence enrichment.

## Project Vision

Threat Intel Analyzer aims to help users investigate suspicious
network activity by collecting security events, applying detection
rules, identifying anomalies, and presenting findings through a
web dashboard.

A detection indicates potentially suspicious behavior. It does not,
by itself, prove that an attack occurred.

## Technology Stack

- Rust: Network event collection and parsing
- Go: Detection engine and REST API
- Python: Statistical analysis and anomaly detection
- React + TypeScript: Security dashboard
- PostgreSQL: Persistent storage
- Docker Compose: Local service orchestration

## Planned Architecture

1. Rust collects or parses supported network events.
2. Go validates events and coordinates detection.
3. Python analyzes event patterns and returns anomaly results.
4. PostgreSQL stores events and findings.
5. React communicates with the Go API to display results.
6. Threat intelligence enriches findings with additional context.

## Development Roadmap

- [ ] Phase 0: Project foundation and event contracts
- [ ] Phase 1: Python anomaly detector
- [ ] Phase 2: Go detection engine and REST API
- [ ] Phase 3: PostgreSQL integration
- [ ] Phase 4: Rust network event collector
- [ ] Phase 5: React + TypeScript dashboard
- [ ] Phase 6: Threat intelligence enrichment
- [ ] Phase 7: Integration and security testing
- [ ] Phase 8: Docker Compose and final documentation

## Project Status

Initial repository setup. Application components have not yet
been implemented.

## Development Principles

- Build and test one component at a time.
- Use a shared, documented event format.
- Keep detection results explainable.
- Handle errors explicitly.
- Protect credentials and sensitive data.
- Collect or analyze only data we are authorized to access.

## License

License not yet selected.
EOF