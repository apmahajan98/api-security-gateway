import os
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import DateTime, Float, Index, Integer, JSON, String, Text, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://api_security:change-me-locally@localhost:5433/api_security",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_occurred_at", "occurred_at"),
        Index("ix_security_events_decision_occurred_at", "decision", "occurred_at"),
        Index("ix_security_events_route_occurred_at", "path", "occurred_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    request_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    decision: Mapped[str] = mapped_column(String(16), nullable=False)
    classification: Mapped[str] = mapped_column(String(32), nullable=False)
    detector: Mapped[str] = mapped_column(String(128), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(64))
    rule_decision: Mapped[str | None] = mapped_column(String(16))
    rule_reason_code: Mapped[str | None] = mapped_column(String(64))
    risk: Mapped[str] = mapped_column(String(16), nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)
    simulation: Mapped[dict[str, Any] | None] = mapped_column(JSON)
    ml_result: Mapped[dict[str, Any] | None] = mapped_column(JSON)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_status_last_seen", "status", "last_seen"),
        Index("ix_incidents_fingerprint_status", "fingerprint", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(256), nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(2048), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    detector: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)


def db_available() -> bool:
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        return True
    except Exception:
        return False


def risk_for(decision: str, ml_result: dict[str, Any] | None) -> tuple[str, float]:
    if decision == "block":
        return "High", 0.85
    if decision == "review":
        score = float((ml_result or {}).get("score", 0.68))
        return ("Critical" if score >= 0.9 else "High" if score >= 0.75 else "Medium"), score
    return "Low", 0.08


def incident_title(reason_code: str | None, decision: str) -> str:
    labels = {
        "SQL_INJECTION": "SQL injection attempt",
        "XSS_ATTEMPT": "Cross-site scripting attempt",
        "PATH_TRAVERSAL": "Path traversal attempt",
        "API_ABUSE": "Possible API abuse",
        "CREDENTIAL_STUFFING": "Credential stuffing",
        "DATA_EXPORT": "Suspicious data export",
    }
    return labels.get(reason_code or "", "Anomalous API activity" if decision == "review" else "Blocked API request")


def persist_inspection(result: dict[str, Any], payload: dict[str, Any]) -> None:
    now = datetime.now(timezone.utc)
    risk, risk_score = risk_for(result["decision"], result.get("ml"))
    with SessionLocal.begin() as session:
        session.add(
            SecurityEvent(
                request_id=result["request_id"],
                occurred_at=now,
                method=result["method"],
                path=result["path"],
                decision=result["decision"],
                classification=result["classification"],
                detector=result["detector"],
                reason_code=result.get("reason_code"),
                rule_decision=result.get("rule_decision"),
                rule_reason_code=result.get("rule_reason_code"),
                risk=risk,
                latency_ms=result["latency_ms"],
                simulation=payload.get("simulation"),
                ml_result=result.get("ml"),
            )
        )
        if result["decision"] != "allow":
            fingerprint = f"{result['path']}:{result.get('reason_code') or result['decision']}"
            incident = session.scalar(
                select(Incident).where(Incident.fingerprint == fingerprint, Incident.status == "open")
            )
            if incident:
                incident.event_count += 1
                incident.last_seen = now
                incident.risk_score = max(incident.risk_score, risk_score)
            else:
                session.add(
                    Incident(
                        fingerprint=fingerprint,
                        title=incident_title(result.get("reason_code"), result["decision"]),
                        endpoint=result["path"],
                        severity=risk,
                        risk_score=risk_score,
                        detector=result["detector"],
                        first_seen=now,
                        last_seen=now,
                    )
                )


def serialize_event(event: SecurityEvent) -> dict[str, Any]:
    return {
        "time": event.occurred_at.isoformat(),
        "requestId": event.request_id,
        "method": event.method,
        "path": event.path,
        "decision": {"block": "Blocked", "review": "Anomaly review", "allow": "Allowed"}.get(event.decision, event.decision),
        "detector": event.detector,
        "risk": event.risk,
        "latency": f"{event.latency_ms:g} ms",
        "reason": event.reason_code or "",
    }


def recent_events(limit: int = 50) -> list[dict[str, Any]]:
    with SessionLocal() as session:
        rows = session.scalars(select(SecurityEvent).order_by(SecurityEvent.occurred_at.desc()).limit(limit)).all()
        return [serialize_event(row) for row in rows]


def active_incidents(limit: int = 20) -> list[dict[str, Any]]:
    with SessionLocal() as session:
        rows = session.scalars(
            select(Incident).where(Incident.status == "open").order_by(Incident.last_seen.desc()).limit(limit)
        ).all()
        return [
            {
                "id": row.id,
                "title": row.title,
                "endpoint": row.endpoint,
                "severity": row.severity,
                "risk_score": row.risk_score,
                "detector": row.detector,
                "event_count": row.event_count,
                "first_seen": row.first_seen.isoformat(),
                "last_seen": row.last_seen.isoformat(),
            }
            for row in rows
        ]


def overview_metrics() -> dict[str, Any]:
    with SessionLocal() as session:
        today = datetime.now(timezone.utc).date()
        total = session.scalar(select(func.count(SecurityEvent.id)).where(func.date(SecurityEvent.occurred_at) == today)) or 0
        blocked = session.scalar(select(func.count(SecurityEvent.id)).where(SecurityEvent.decision == "block", func.date(SecurityEvent.occurred_at) == today)) or 0
        anomalies = session.scalar(select(func.count(SecurityEvent.id)).where(SecurityEvent.decision == "review", func.date(SecurityEvent.occurred_at) == today)) or 0
        p95 = session.scalar(select(func.percentile_cont(0.95).within_group(SecurityEvent.latency_ms)).where(func.date(SecurityEvent.occurred_at) == today))
        return {"requests_today": total, "blocked_today": blocked, "anomalies_today": anomalies, "p95_latency_ms": round(float(p95 or 0), 2)}
