# Gateway Architecture

## Overview

The gateway is a modular monolith that separates HTTP transport, request
normalization, detection, decision policy, and audit persistence. The service
uses one process boundary for the initial deployment and exposes internal
interfaces so detection and storage implementations can evolve independently.

```text
                         +----------------------+
                         | PostgreSQL           |
                         | structured audit     |
                         | events               |
                         +----------^-----------+
                                    |
                                    |
+--------+     +--------------------+--------------------+     +-----------+
| Client | --> | Gateway API                              | --> | Protected |
+--------+     |                                           |     | API       |
               | ingress                                  |     +-----------+
               |   -> authentication and validation       |
               |   -> request normalization               |
               |   -> detector pipeline                   |
               |   -> decision policy                     |
               |   -> audit writer                        |
               +-------------------------------------------+
                              |
                              v
                  +--------------------------+
                  | Anomaly-detector adapter |
                  +--------------------------+
```

## Processing pipeline

### Ingress

The ingress layer receives the HTTP request, assigns a request ID, records a
monotonic start time, and applies transport-level limits. It is responsible for
returning consistent status codes and preventing oversized or malformed input
from entering the detector pipeline.

### Authentication and validation

Authentication establishes the request identity used by downstream policy.
Schema validation checks required fields, types, lengths, and endpoint-specific
constraints. Authentication and validation failures are rejected before the
request is forwarded.

### Request normalization

The normalizer converts framework-specific request data into an internal
representation containing method, route template, identity metadata, selected
header attributes, query metadata, and a bounded body representation. Secrets
and credentials are removed before the representation is passed to detectors
or audit code.

### Detector pipeline

The deterministic rule detector evaluates known patterns and policy violations.
It returns a normalized result containing detector name, classification,
reason code, and optional evidence metadata that has already been redacted.

The anomaly-detector adapter exposes the same result shape for statistical or
machine-learning detectors. Its contract includes detector name, model or
configuration version, score, threshold, and classification. The transport
layer does not depend on a particular model framework.

### Decision policy

The decision service combines detector results and produces an explicit
decision:

- `allow`: forward the request to the protected API.
- `block`: terminate the request at the gateway and return a safe error.
- `review`: route the request according to the deployment's review policy.

Decision policy is separate from detection so a detector can be evaluated,
thresholded, or disabled without changing HTTP routing code. A high-confidence
rule violation includes a stable reason code in the internal decision and
audit event.

### Audit writer

The audit writer maps the decision to a structured PostgreSQL record. It stores
security metadata, not a copy of the request. Audit persistence is isolated
from the request decision path so a database interruption does not silently
convert a blocked request into an allowed request or introduce unbounded
request latency.

## Data contract

An audit event contains:

- request ID;
- UTC timestamp;
- HTTP method and route template;
- decision and downstream response status;
- detector name and classification;
- reason code, when present;
- score, threshold, and model version, when applicable;
- bounded gateway latency;
- a truncated, non-reversible correlation identifier, when required.

An audit event excludes authorization headers, cookies, passwords, API keys,
access tokens, complete request bodies, raw uploaded files, and unnecessary
personal information. Correlation identifiers are hashed or otherwise
irreversibly transformed before persistence.

## Failure behavior

Malformed requests fail validation and are not forwarded. Deterministic rule
matches produce a block decision. Detector timeouts and dependency failures
are handled according to the configured policy and are observable as
operational events. Audit-store failures are isolated from the security
decision and must not cause credentials or raw request data to be written to
fallback logs.

Liveness checks indicate whether the gateway process is running. Readiness
checks indicate whether required dependencies, including PostgreSQL where
configured, are available for traffic handling.

## Persistence and deployment topology

Local development uses Docker Compose with a gateway container and PostgreSQL.
The same service boundary can be packaged as a container and deployed through
Helm to an authorized Kubernetes or AWS environment. Configuration, database
credentials, detector thresholds, and model settings are supplied at runtime;
they are not embedded in the image or source repository.

## Observability

Operational telemetry includes request counts by decision, detector latency,
total gateway latency, downstream status, audit-write outcomes, and dependency
health. Logs use request IDs and reason codes for correlation and omit secrets,
authorization material, and raw payloads.

## Evaluation model

Evaluation uses versioned synthetic data and authorized test traffic. The
measurement surface includes p50, p95, and p99 gateway-added latency,
throughput, CPU and memory usage, and the confusion-matrix counts for each
detector. Each result records the dataset composition, threshold, model
version, hardware, and known limitations.
