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
- Explicit `allow`, `block`, and `review` outcomes.
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
the protected API in the planned proxy deployment. In the current prototype,
`/inspect` is a controlled inspection endpoint and does not forward traffic.
Blocked requests terminate at the gateway and receive a response that exposes
a safe reason code without revealing detector internals.

## Detection model

The rule detector is the explainable baseline. Rules operate on normalized
request attributes and identify patterns such as malformed input, suspicious
query syntax, and violations of endpoint authorization policy. Each rule
returns a detector result and, when applicable, a stable reason code.

The anomaly-detector adapter defines the integration boundary for a later
statistical or machine-learning detector. An adapter can return a detector
name, score, threshold, model version, and classification without changing
the gateway transport or audit interfaces.

The current playground uses this adapter through the same `/inspect` endpoint.
It sends a bounded, synthetic behavior summary rather than exposing raw
payload controls. The gateway runs deterministic rules first, then the local
ML detector when the trained artifact and cached Hugging Face model are
available. An ML anomaly produces a `review` decision so the model can surface
unusual behavior without replacing hard security rules. `/system/status`
exposes whether the local model is loaded.

## Audit and data protection

Audit events contain request ID, timestamp, HTTP method, route template,
decision, response status, detector result, reason code, bounded latency, and a
non-reversible correlation identifier where required.

The current prototype keeps dashboard events in browser memory. The planned
database writer will not persist authorization headers, cookies, passwords,
API keys, tokens, complete request bodies, or unnecessary personal data.
Request content is inspected only within configured size limits and is not
copied into logs or audit records. Database credentials are supplied through
runtime configuration rather than application data.

## Technology

- Python and FastAPI provide the HTTP service and API contracts.
- PostgreSQL and SQLAlchemy are the planned structured audit persistence layer.
- Docker Compose supplies the local gateway and database environment.
- Helm packages the service for Kubernetes-based deployment.
- AWS is the target deployment environment for authorized testing.

## Current implementation status

The current milestone includes the FastAPI inspection endpoint, static security
rules, the reusable CPU-based ML anomaly detector, the synthetic request
playground, and the dashboard health/status views. The dashboard's initial KPI
cards, chart, incidents, API inventory, and event rows are representative
showcase data; a simulation adds real results to the current browser session.

PostgreSQL persistence is wired into the inspection path. Protected-API
forwarding, authentication, and Helm/AWS deployment remain future milestones.

### PostgreSQL event persistence

The gateway stores sanitized inspection metadata in PostgreSQL. Raw request
bodies and query strings are never written to the database. The schema is in
`db/init/001_schema.sql` and is also created by the application on startup.

Start the database and gateway with:

```bash
docker compose up --build
```

The dashboard reads persisted data through `GET /api/events`,
`GET /api/incidents`, and `GET /api/overview`. Set `DATABASE_URL` when running
outside Compose; the local default is the value in `.env.example`.

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

## Developer quick start

Clone the repository, create a virtual environment, and install the project
with development dependencies:

```bash
git clone <repository-url>
cd 272_project
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
cp .env.example .env
```

Run the checks:

```bash
python -m pytest -q
ruff check .
ruff format --check .
```

Start the API directly with `python -m uvicorn app.main:app --reload`, or start
the API and PostgreSQL together with `docker compose up --build`. The initial
service exposes `/health`, `/ready`, `/system/status`, and the interactive API
reference at `/docs`.

Team branching, pull requests, review requirements, ownership boundaries, and
local setup details are defined in [`CONTRIBUTING.md`](CONTRIBUTING.md).

## ML experiment quick start

Generate synthetic traffic, train the local CPU-based anomaly detector, and
evaluate it:

```bash
python -m scripts.generate_traffic
python -m scripts.train_anomaly_model
python -m scripts.tune_anomaly_model
python -m scripts.evaluate_anomaly_model
```

The training set contains normal behavior only. A separate validation set is
used to tune the decision threshold, and the final evaluation set measures
the result on unseen controlled traffic such as high request volume, repeated
login failures, unusual data exports, and route spraying.

Training configuration and reproducibility instructions are in
[`docs/ML_TRAINING.md`](docs/ML_TRAINING.md). Generated model artifacts are
not committed; they can be rebuilt from the tracked scripts and configuration.
