import json
import re
import time
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field


app = FastAPI(
    title="API Security and Anomaly Detection Gateway",
    version="0.1.0",
)

BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


class InspectRequest(BaseModel):
    """Bounded, redacted request representation for the rule detector."""

    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    path: str = Field(min_length=1, max_length=2048)
    query: str = Field(default="", max_length=4096)
    body: Any = None


INJECTION_RULES = (
    (re.compile(r"\bunion\s+select\b", re.IGNORECASE), "SQL_INJECTION"),
    (re.compile(r"(?:'|%27)\s*(?:or|and)\s+[^\s]+\s*=\s*[^\s]+", re.IGNORECASE), "SQL_INJECTION"),
    (re.compile(r"<script\b", re.IGNORECASE), "XSS_ATTEMPT"),
    (re.compile(r"(?:\.\./|%2e%2e%2f)", re.IGNORECASE), "PATH_TRAVERSAL"),
)


def _inspect_request(payload: InspectRequest) -> tuple[str, str | None]:
    """Return the decision and stable reason code without persisting raw input."""
    body_text = json.dumps(payload.body, separators=(",", ":"), default=str)
    inspected_text = "\n".join((payload.path, payload.query, body_text))
    for rule, reason_code in INJECTION_RULES:
        if rule.search(inspected_text):
            return "block", reason_code
    return "allow", None


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


@app.post("/inspect", tags=["inspection"])
def inspect_request(payload: InspectRequest) -> dict[str, Any]:
    """Inspect a bounded synthetic request and return a safe gateway decision."""
    started = time.perf_counter()
    decision, reason_code = _inspect_request(payload)
    latency_ms = round((time.perf_counter() - started) * 1000, 2)
    return {
        "request_id": f"req_{uuid4().hex[:10]}",
        "method": payload.method,
        "path": payload.path,
        "decision": decision,
        "detector": "rule-detector",
        "classification": "malicious" if decision == "block" else "benign",
        "reason_code": reason_code,
        "latency_ms": latency_ms,
    }
