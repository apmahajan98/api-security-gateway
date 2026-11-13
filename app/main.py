import json
import os
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.detectors.ml_anomaly import MLAnomalyDetector
from app.ml.features import TrafficWindow

app = FastAPI(
    title="API Security and Anomaly Detection Gateway",
    version="0.1.0",
)

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR.parent / "models" / "anomaly_detector.joblib"
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


class SimulationTraffic(BaseModel):
    """Bounded behavior summary used by the controlled playground only."""

    requests_per_minute: float = Field(ge=0, le=100_000)
    failed_logins_per_minute: float = Field(ge=0, le=100_000)
    unique_routes: int = Field(ge=0, le=10_000)
    average_request_bytes: float = Field(ge=0, le=10_000_000)
    average_response_bytes: float = Field(ge=0, le=100_000_000)
    error_rate: float = Field(ge=0, le=1)
    client_profile: Literal["consumer", "employee", "service"] = "consumer"
    hour_of_day: int = Field(default=12, ge=0, le=23)
    session_age_minutes: float = Field(default=30, ge=0, le=100_000)
    new_routes: int = Field(default=0, ge=0, le=10_000)
    location_changed: int = Field(default=0, ge=0, le=1)


class InspectRequest(BaseModel):
    """Bounded, redacted request representation for the rule detector."""

    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    path: str = Field(min_length=1, max_length=2048)
    query: str = Field(default="", max_length=4096)
    body: Any = None
    simulation: SimulationTraffic | None = None


INJECTION_RULES = (
    (re.compile(r"\bunion\s+select\b", re.IGNORECASE), "SQL_INJECTION"),
    (re.compile(r"(?:'|%27)\s*(?:or|and)\s+[^\s]+\s*=\s*[^\s]+", re.IGNORECASE), "SQL_INJECTION"),
    (re.compile(r"<script\b", re.IGNORECASE), "XSS_ATTEMPT"),
    (re.compile(r"(?:\.\./|%2e%2e%2f)", re.IGNORECASE), "PATH_TRAVERSAL"),
)


def _inspect_request(payload: InspectRequest) -> tuple[str, str | None]:
    """Return the decision and stable reason code without persisting raw input."""
    body_text = json.dumps(payload.body, separators=(",", ":"), default=str)
    inspected_text = f"{payload.path}\n{payload.query}\n{body_text}"
    for rule, reason_code in INJECTION_RULES:
        if rule.search(inspected_text):
            return "block", reason_code
    return "allow", None


def _traffic_window(payload: InspectRequest) -> TrafficWindow:
    """Convert the playground's bounded summary into the ML input contract."""
    if payload.simulation is not None:
        return TrafficWindow(
            method=payload.method,
            route=payload.path,
            **payload.simulation.model_dump(),
        )

    body_text = json.dumps(payload.body, separators=(",", ":"), default=str)
    return TrafficWindow(
        method=payload.method,
        route=payload.path,
        requests_per_minute=6,
        failed_logins_per_minute=0,
        unique_routes=1,
        average_request_bytes=max(len(payload.query.encode()), len(body_text.encode())),
        average_response_bytes=1200,
        error_rate=0.01,
    )


@lru_cache(maxsize=1)
def _load_ml_detector() -> MLAnomalyDetector | None:
    """Load the local model once without making a network request at runtime."""
    if os.getenv("ML_ENABLED", "true").lower() in {"0", "false", "no"}:
        return None
    if not MODEL_PATH.exists():
        return None
    try:
        return MLAnomalyDetector(MODEL_PATH, device="cpu", local_files_only=True)
    except (OSError, KeyError, RuntimeError, ValueError):
        # Rules remain available when the optional local model is unavailable.
        return None


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    """Serve the gateway operations dashboard."""
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    """Return a process-level liveness response."""
    return {"status": "ok"}


@app.get("/ready", tags=["system"])
def ready() -> dict[str, str]:
    """Return readiness for the initial dependency-free service skeleton."""
    return {"status": "ready"}


@app.get("/system/status", tags=["system"])
def system_status() -> dict[str, Any]:
    """Return gateway and optional detector readiness for the dashboard."""
    detector = _load_ml_detector()
    return {
        "gateway": "healthy",
        "rule_engine": "loaded",
        "ml": detector.health() if detector else {"status": "unavailable"},
        "model_artifact": str(MODEL_PATH.name) if MODEL_PATH.exists() else None,
    }


@app.post("/inspect", tags=["inspection"])
def inspect_request(payload: InspectRequest) -> dict[str, Any]:
    """Inspect a request with rules first and ML behavior analysis when supplied."""
    started = time.perf_counter()
    rule_decision, rule_reason_code = _inspect_request(payload)
    ml_result = None
    # Anomaly detection needs a time-window summary. The playground supplies
    # one explicitly; ordinary single requests are evaluated by rules only.
    if payload.simulation is not None:
        detector = _load_ml_detector()
        if detector is not None:
            ml_result = detector.analyze(_traffic_window(payload))

    if rule_decision == "block":
        decision = "block"
        reason_code = rule_reason_code
    elif ml_result and ml_result.status == "anomaly":
        decision = "review"
        reason_code = ml_result.reason_code
    else:
        decision = "allow"
        reason_code = None

    latency_ms = round((time.perf_counter() - started) * 1000, 2)
    return {
        "request_id": f"req_{uuid4().hex[:10]}",
        "method": payload.method,
        "path": payload.path,
        "decision": decision,
        "detector": "rule + ml-anomaly" if ml_result else "rule-detector",
        "classification": "malicious"
        if decision == "block"
        else "anomalous"
        if decision == "review"
        else "benign",
        "reason_code": reason_code,
        "rule_decision": rule_decision,
        "rule_reason_code": rule_reason_code,
        "ml": ml_result.as_dict() if ml_result else None,
        "latency_ms": latency_ms,
    }
