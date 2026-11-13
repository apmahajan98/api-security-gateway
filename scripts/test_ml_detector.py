"""Smoke-test the reusable ML anomaly-detector adapter."""

from pathlib import Path

from app.detectors import MLAnomalyDetector
from app.ml.features import TrafficWindow

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    detector = MLAnomalyDetector(ROOT / "models" / "anomaly_detector.joblib")

    examples = [
        TrafficWindow("GET", "/products", 6, 0, 2, 430, 2150, 0.02),
        TrafficWindow(
            "GET",
            "/customers/export",
            900,
            35,
            18,
            12000,
            250000,
            0.35,
            client_profile="consumer",
            hour_of_day=2,
            session_age_minutes=5,
            new_routes=12,
            location_changed=1,
        ),
    ]

    print("Model health:", detector.health())
    for example in examples:
        print(detector.analyze(example).as_dict())


if __name__ == "__main__":
    main()
