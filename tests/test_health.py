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


def test_demo_login_accepts_fake_account() -> None:
    response = client.post(
        "/demo/login",
        json={"username": "alice", "password": "demo-password"},
    )

    assert response.status_code == 200
    assert response.json() == {"authenticated": True}


def test_demo_login_treats_sql_like_username_as_data() -> None:
    response = client.post(
        "/demo/login",
        json={"username": "' OR 1=1 --", "password": "anything"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid username or password"}
