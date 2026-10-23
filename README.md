# API Security and Anomaly Detection Gateway

The API Security and Anomaly Detection Gateway is a defensive HTTP gateway
that evaluates API requests before they reach a protected application. It
combines request validation, deterministic security rules, and an extensible
anomaly-detection interface to produce an explicit traffic decision and a
sanitized audit record.

The gateway is designed for security research and controlled integration
testing. It is not a substitute for application authorization, secure coding,
network controls, or an independently validated production Web Application
Firewall.

## Capabilities

The gateway provides the following capabilities:

- HTTP request inspection at the API boundary.
- Input normalization and bounded request representation.
- Deterministic detection of known malicious patterns and policy violations.
- A detector adapter interface for statistical or machine-learning models.
- Explicit `allow`, `block`, and future `review` outcomes.
- Stable reason codes for blocked requests.
- Structured audit events containing security-relevant metadata.
- Latency and detection metrics for controlled evaluation.

## Request processing

```text
Client
  |
  v
Gateway ingress
  |
  +-- authentication and schema validation
  +-- request normalization and size limits
  +-- deterministic rule evaluation
  +-- anomaly-detector adapter
  +-- decision policy
        |
        +-- allow --> protected API
        +-- block --> safe error response
        +-- review --> policy-defined handling
  |
  +-- sanitized audit event --> PostgreSQL
```

The gateway assigns a request identifier, evaluates the request against the
configured detectors, and emits a decision. Allowed requests are forwarded to
the protected API. Blocked requests terminate at the gateway and receive a
response that exposes a safe reason code without revealing detector internals.

## Detection model

The rule detector is the explainable baseline. Rules operate on normalized
request attributes and identify patterns such as malformed input, suspicious
query syntax, and violations of endpoint authorization policy. Each rule
returns a detector result and, when applicable, a stable reason code.

The anomaly-detector adapter defines the integration boundary for a later
statistical or machine-learning detector. An adapter can return a detector
name, score, threshold, model version, and classification without changing
the gateway transport or audit interfaces.

## Audit and data protection

Audit events contain request ID, timestamp, HTTP method, route template,
decision, response status, detector result, reason code, bounded latency, and a
non-reversible correlation identifier where required.

The gateway does not persist authorization headers, cookies, passwords, API
keys, tokens, complete request bodies, or unnecessary personal data. Request
content is inspected only within configured size limits and is not copied into
logs or audit records. Database credentials are supplied through runtime
configuration rather than application data.

## Technology

- Python and FastAPI provide the HTTP service and API contracts.
- PostgreSQL stores structured audit events.
- SQLAlchemy provides database access and persistence models.
- Docker Compose supplies the local gateway and database environment.
- Helm packages the service for Kubernetes-based deployment.
- AWS is the target deployment environment for authorized testing.

## Evaluation

The gateway can be evaluated using versioned synthetic traffic containing
benign requests and authorized security test cases. Evaluation reports should
include gateway-added p50, p95, and p99 latency; throughput; CPU and memory
usage; true positives; false positives; true negatives; false negatives; and
the detector threshold, model version, hardware, and dataset composition.

## Security scope

Use the gateway only with systems and data owned by the team or covered by
explicit testing authorization. Development and evaluation data must be
synthetic or appropriately sanitized. The gateway's detection behavior should
be treated as an experimental security control until independently validated.
