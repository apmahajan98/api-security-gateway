from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_returns_ok() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ready_returns_ready() -> None:
    response = client.get("/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_dashboard_is_served() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert "Sentinel" in response.text


def test_inspect_allows_benign_request() -> None:
    response = client.post(
        "/inspect",
        json={"method": "GET", "path": "/v1/users", "query": "alice"},
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "allow"
    assert response.json()["reason_code"] is None


def test_inspect_blocks_sql_injection_pattern() -> None:
    response = client.post(
        "/inspect",
        json={"method": "GET", "path": "/v1/users", "query": "' OR 1=1 --"},
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "block"
    assert response.json()["reason_code"] == "SQL_INJECTION"


def test_simulation_returns_combined_detection_contract() -> None:
    response = client.post(
        "/inspect",
        json={
            "method": "GET",
            "path": "/customers/export",
            "simulation": {
                "requests_per_minute": 120,
                "failed_logins_per_minute": 2,
                "unique_routes": 12,
                "average_request_bytes": 8000,
                "average_response_bytes": 250000,
                "error_rate": 0.24,
                "client_profile": "consumer",
                "hour_of_day": 3,
                "session_age_minutes": 12,
                "new_routes": 8,
                "location_changed": 1,
            },
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["rule_decision"] == "allow"
    assert payload["decision"] in {"allow", "review"}
    assert "ml" in payload
