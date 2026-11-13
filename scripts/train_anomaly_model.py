"""Train and save the first hybrid API anomaly detector."""

import json
from collections import defaultdict
from pathlib import Path

import joblib
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.ensemble import IsolationForest

from app.ml.features import TrafficWindow, to_behavior_features

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "configs" / "ml_config.json"
NORMAL_PATH = ROOT / "data" / "normal_behavior.jsonl"
MODEL_PATH = ROOT / "models" / "anomaly_detector.joblib"


def load_windows(path: Path) -> list[TrafficWindow]:
    with path.open(encoding="utf-8") as file:
        return [TrafficWindow(**json.loads(line)) for line in file if line.strip()]


def main() -> None:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    model_name = config["embedding_model"]
    isolation_config = config["isolation_forest"]
    windows = load_windows(NORMAL_PATH)
    embedding_model = SentenceTransformer(model_name, device=config["device"])

    semantic_embeddings = embedding_model.encode(
        [window.semantic_summary() for window in windows],
        normalize_embeddings=True,
    )

    behavior_detector = IsolationForest(
        contamination=isolation_config["contamination"],
        n_estimators=isolation_config["n_estimators"],
        random_state=config["random_state"],
    )
    semantic_detector = IsolationForest(
        contamination=isolation_config["contamination"],
        n_estimators=isolation_config["n_estimators"],
        random_state=config["random_state"],
    )
    behavior_features = np.vstack([to_behavior_features(window) for window in windows])
    behavior_detector.fit(behavior_features)
    semantic_detector.fit(semantic_embeddings)

    windows_by_profile = defaultdict(list)
    for window in windows:
        windows_by_profile[window.client_profile].append(window)

    profile_detectors = {}
    for profile, profile_windows in windows_by_profile.items():
        profile_detector = IsolationForest(
            contamination=isolation_config["contamination"],
            n_estimators=isolation_config["n_estimators"],
            random_state=config["random_state"],
        )
        profile_features = np.vstack([to_behavior_features(window) for window in profile_windows])
        profile_detector.fit(profile_features)
        profile_detectors[profile] = profile_detector

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model_version": config["model_version"],
            "embedding_model": model_name,
            "behavior_detector": behavior_detector,
            "behavior_detectors": profile_detectors,
            "semantic_detector": semantic_detector,
        },
        MODEL_PATH,
    )

    print(f"Trained on {len(windows)} normal traffic windows")
    print(f"Saved model to {MODEL_PATH}")


if __name__ == "__main__":
    main()
