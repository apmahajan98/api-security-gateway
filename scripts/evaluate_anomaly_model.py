"""Evaluate the saved anomaly detector on synthetic anomalous traffic."""

import json
from pathlib import Path

import joblib
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from app.ml.features import TrafficWindow, to_behavior_features

ROOT = Path(__file__).resolve().parents[1]
EVALUATION_PATH = ROOT / "data" / "evaluation_behavior.jsonl"
MODEL_PATH = ROOT / "models" / "anomaly_detector.joblib"


def load_labeled_windows(path: Path) -> tuple[list[TrafficWindow], np.ndarray]:
    windows = []
    labels = []
    with path.open(encoding="utf-8") as file:
        for line in file:
            if line.strip():
                payload = json.loads(line)
                labels.append(int(payload.pop("label")))
                windows.append(TrafficWindow(**payload))
    return windows, np.array(labels, dtype=int)


def profile_behavior_scores(windows: list[TrafficWindow], bundle: dict) -> np.ndarray:
    detectors = bundle.get("behavior_detectors", {})
    fallback = bundle["behavior_detector"]
    scores = []
    for window in windows:
        detector = detectors.get(window.client_profile, fallback)
        features = to_behavior_features(window).reshape(1, -1)
        scores.append(detector.decision_function(features)[0])
    return np.array(scores)


def main() -> None:
    windows, expected = load_labeled_windows(EVALUATION_PATH)
    bundle = joblib.load(MODEL_PATH)
    embedding_model = SentenceTransformer(bundle["embedding_model"], device="cpu")

    semantic_embeddings = embedding_model.encode(
        [window.semantic_summary() for window in windows],
        normalize_embeddings=True,
    )

    behavior_scores = profile_behavior_scores(windows, bundle)
    semantic_scores = bundle["semantic_detector"].decision_function(semantic_embeddings)
    decision = bundle.get("decision", {"semantic_weight": 0.0, "threshold": 0.0})
    combined_scores = behavior_scores + decision["semantic_weight"] * semantic_scores
    predictions = (combined_scores < decision["threshold"]).astype(int)
    print("Evaluation set: mixed normal and anomalous traffic")
    print("Samples:", len(windows))
    print("Semantic weight:", round(decision["semantic_weight"], 4))
    print("Threshold:", round(decision["threshold"], 4))
    print("Accuracy:", round(accuracy_score(expected, predictions), 4))
    print("Precision:", round(precision_score(expected, predictions, zero_division=0), 4))
    print("Recall:", round(recall_score(expected, predictions, zero_division=0), 4))
    print("F1 score:", round(f1_score(expected, predictions, zero_division=0), 4))
    print("Confusion matrix [[true_normal, false_anomaly], [missed_anomaly, true_anomaly]]:")
    print(confusion_matrix(expected, predictions, labels=[0, 1]))


if __name__ == "__main__":
    main()
