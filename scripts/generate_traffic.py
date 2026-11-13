"""Generate realistic synthetic normal and anomalous API traffic windows."""

import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
NORMAL_PATH = DATA_DIR / "normal_behavior.jsonl"
VALIDATION_PATH = DATA_DIR / "validation_behavior.jsonl"
EVALUATION_PATH = DATA_DIR / "evaluation_behavior.jsonl"
SEED = 42


def consumer_window(rng: random.Random) -> dict[str, object]:
    method, route = rng.choice(
        (("GET", "/products"), ("GET", "/users/profile"), ("POST", "/orders"))
    )
    return {
        "method": method,
        "route": route,
        "requests_per_minute": rng.randint(2, 15),
        "failed_logins_per_minute": rng.randint(0, 1),
        "unique_routes": rng.randint(1, 4),
        "average_request_bytes": rng.randint(250, 900),
        "average_response_bytes": rng.randint(700, 6000),
        "error_rate": round(rng.uniform(0.0, 0.05), 4),
        "client_profile": "consumer",
        "hour_of_day": rng.randint(7, 23),
        "session_age_minutes": rng.randint(2, 240),
        "new_routes": rng.randint(0, 1),
        "location_changed": 0,
    }


def employee_window(rng: random.Random) -> dict[str, object]:
    method, route = rng.choice(
        (("GET", "/customers/search"), ("GET", "/reports"), ("GET", "/reports/export"))
    )
    return {
        "method": method,
        "route": route,
        "requests_per_minute": rng.randint(1, 10),
        "failed_logins_per_minute": rng.randint(0, 1),
        "unique_routes": rng.randint(2, 7),
        "average_request_bytes": rng.randint(400, 1800),
        "average_response_bytes": rng.randint(
            1000, 300000 if route == "/reports/export" else 12000
        ),
        "error_rate": round(rng.uniform(0.0, 0.08), 4),
        "client_profile": "employee",
        "hour_of_day": rng.randint(7, 19),
        "session_age_minutes": rng.randint(10, 480),
        "new_routes": rng.randint(0, 2),
        "location_changed": 0,
    }


def service_window(rng: random.Random) -> dict[str, object]:
    method, route = rng.choice(
        (("GET", "/internal/metrics"), ("POST", "/inventory/sync"), ("GET", "/health"))
    )
    return {
        "method": method,
        "route": route,
        "requests_per_minute": rng.randint(80, 260),
        "failed_logins_per_minute": 0,
        "unique_routes": rng.randint(1, 3),
        "average_request_bytes": rng.randint(300, 1800),
        "average_response_bytes": rng.randint(500, 12000),
        "error_rate": round(rng.uniform(0.0, 0.03), 4),
        "client_profile": "service",
        "hour_of_day": rng.randint(0, 23),
        "session_age_minutes": rng.randint(1, 60),
        "new_routes": 0,
        "location_changed": 0,
    }


def normal_window(rng: random.Random) -> dict[str, object]:
    generator = rng.choices(
        (consumer_window, employee_window, service_window),
        weights=(0.60, 0.25, 0.15),
        k=1,
    )[0]
    return generator(rng)


def high_volume_window(rng: random.Random) -> dict[str, object]:
    return {
        "method": "GET",
        "route": "/products",
        "requests_per_minute": rng.randint(300, 1200),
        "failed_logins_per_minute": rng.randint(0, 8),
        "unique_routes": rng.randint(8, 25),
        "average_request_bytes": rng.randint(500, 3000),
        "average_response_bytes": rng.randint(1000, 50000),
        "error_rate": round(rng.uniform(0.08, 0.35), 4),
        "client_profile": "consumer",
        "hour_of_day": rng.randint(0, 23),
        "session_age_minutes": rng.randint(1, 30),
        "new_routes": rng.randint(5, 20),
        "location_changed": rng.choice((0, 1)),
    }


def credential_abuse_window(rng: random.Random) -> dict[str, object]:
    return {
        "method": "POST",
        "route": "/auth/login",
        "requests_per_minute": rng.randint(20, 100),
        "failed_logins_per_minute": rng.randint(20, 80),
        "unique_routes": rng.randint(1, 3),
        "average_request_bytes": rng.randint(300, 900),
        "average_response_bytes": rng.randint(500, 2500),
        "error_rate": round(rng.uniform(0.35, 0.95), 4),
        "client_profile": "consumer",
        "hour_of_day": rng.randint(0, 23),
        "session_age_minutes": rng.randint(0, 10),
        "new_routes": 0,
        "location_changed": rng.choice((0, 1)),
    }


def data_export_window(rng: random.Random) -> dict[str, object]:
    return {
        "method": "GET",
        "route": "/customers/export",
        "requests_per_minute": rng.randint(30, 180),
        "failed_logins_per_minute": rng.randint(0, 5),
        "unique_routes": rng.randint(5, 20),
        "average_request_bytes": rng.randint(1000, 12000),
        "average_response_bytes": rng.randint(100000, 500000),
        "error_rate": round(rng.uniform(0.05, 0.4), 4),
        "client_profile": "consumer",
        "hour_of_day": rng.randint(0, 23),
        "session_age_minutes": rng.randint(1, 30),
        "new_routes": rng.randint(3, 15),
        "location_changed": 1,
    }


def route_spray_window(rng: random.Random) -> dict[str, object]:
    return {
        "method": "GET",
        "route": rng.choice(("/admin", "/payments", "/customers/export")),
        "requests_per_minute": rng.randint(20, 90),
        "failed_logins_per_minute": rng.randint(0, 15),
        "unique_routes": rng.randint(10, 30),
        "average_request_bytes": rng.randint(500, 5000),
        "average_response_bytes": rng.randint(2000, 30000),
        "error_rate": round(rng.uniform(0.1, 0.6), 4),
        "client_profile": "consumer",
        "hour_of_day": rng.randint(0, 23),
        "session_age_minutes": rng.randint(1, 40),
        "new_routes": rng.randint(10, 30),
        "location_changed": rng.choice((0, 1)),
    }


def slow_exfiltration_window(rng: random.Random) -> dict[str, object]:
    return {
        "method": "GET",
        "route": "/customers/export",
        "requests_per_minute": rng.randint(8, 25),
        "failed_logins_per_minute": rng.randint(0, 3),
        "unique_routes": rng.randint(2, 8),
        "average_request_bytes": rng.randint(800, 6000),
        "average_response_bytes": rng.randint(250000, 1000000),
        "error_rate": round(rng.uniform(0.05, 0.25), 4),
        "client_profile": "consumer",
        "hour_of_day": rng.randint(0, 5),
        "session_age_minutes": rng.randint(1, 20),
        "new_routes": rng.randint(1, 6),
        "location_changed": 1,
    }


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        for row in rows:
            file.write(json.dumps(row) + "\n")


def labeled_rows(
    rng: random.Random,
    normal_count: int,
    anomaly_count_per_type: int,
) -> list[dict[str, object]]:
    anomaly_generators = (
        high_volume_window,
        credential_abuse_window,
        data_export_window,
        route_spray_window,
        slow_exfiltration_window,
    )
    rows = [{**normal_window(rng), "label": 0} for _ in range(normal_count)]
    for generator in anomaly_generators:
        rows.extend({**generator(rng), "label": 1} for _ in range(anomaly_count_per_type))
    rng.shuffle(rows)
    return rows


def main() -> None:
    rng = random.Random(SEED)
    normal_rows = [normal_window(rng) for _ in range(1000)]
    validation_rows = labeled_rows(rng, normal_count=150, anomaly_count_per_type=30)
    evaluation_rows = labeled_rows(rng, normal_count=150, anomaly_count_per_type=30)

    write_jsonl(NORMAL_PATH, normal_rows)
    write_jsonl(VALIDATION_PATH, validation_rows)
    write_jsonl(EVALUATION_PATH, evaluation_rows)

    print(f"Wrote {len(normal_rows)} normal training windows to {NORMAL_PATH}")
    print(f"Wrote {len(validation_rows)} labeled validation windows to {VALIDATION_PATH}")
    print(f"Wrote {len(evaluation_rows)} labeled evaluation windows to {EVALUATION_PATH}")


if __name__ == "__main__":
    main()
