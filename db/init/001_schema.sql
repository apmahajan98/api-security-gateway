CREATE TABLE IF NOT EXISTS security_events (
    id SERIAL PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL UNIQUE,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    method VARCHAR(10) NOT NULL,
    path VARCHAR(2048) NOT NULL,
    decision VARCHAR(16) NOT NULL CHECK (decision IN ('allow', 'block', 'review')),
    classification VARCHAR(32) NOT NULL,
    detector VARCHAR(128) NOT NULL,
    reason_code VARCHAR(64),
    rule_decision VARCHAR(16),
    rule_reason_code VARCHAR(64),
    risk VARCHAR(16) NOT NULL,
    latency_ms DOUBLE PRECISION NOT NULL,
    simulation JSONB,
    ml_result JSONB
);

CREATE INDEX IF NOT EXISTS ix_security_events_occurred_at ON security_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_security_events_decision_occurred_at ON security_events (decision, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_security_events_route_occurred_at ON security_events (path, occurred_at DESC);

CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    fingerprint VARCHAR(256) NOT NULL,
    title VARCHAR(160) NOT NULL,
    endpoint VARCHAR(2048) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    risk_score DOUBLE PRECISION NOT NULL,
    detector VARCHAR(128) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'open',
    event_count INTEGER NOT NULL DEFAULT 1,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_incidents_status_last_seen ON incidents (status, last_seen DESC);
CREATE INDEX IF NOT EXISTS ix_incidents_fingerprint_status ON incidents (fingerprint, status);
