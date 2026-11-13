"""Tune the hybrid detector decision threshold on labeled validation data."""

import json
from pathlib import Path

import joblib
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

from app.ml.features import TrafficWindow, to_behavior_features

ROOT = Path(__file__).resolve().parents[1]
VALIDATION_PATH = ROOT / "data" / "validation_behavior.jsonl"
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
    windows, expected = load_labeled_windows(VALIDATION_PATH)
    bundle = joblib.load(MODEL_PATH)
    embedding_model = SentenceTransformer(bundle["embedding_model"], device="cpu")

    semantic_embeddings = embedding_model.encode(
        [window.semantic_summary() for window in windows],
        normalize_embeddings=True,
    )

    behavior_scores = profile_behavior_scores(windows, bundle)
    semantic_scores = bundle["semantic_detector"].decision_function(semantic_embeddings)

    best = None
    for semantic_weight in np.linspace(0.0, 1.0, 21):
        combined_scores = behavior_scores + semantic_weight * semantic_scores
        for threshold in np.linspace(combined_scores.min(), combined_scores.max(), 401):
            predictions = (combined_scores < threshold).astype(int)
            metrics = {
                "accuracy": accuracy_score(expected, predictions),
                "precision": precision_score(expected, predictions, zero_division=0),
                "recall": recall_score(expected, predictions, zero_division=0),
                "f1": f1_score(expected, predictions, zero_division=0),
            }
            # The project currently optimizes accuracy, then F1 and recall.
            # Revisit this objective when production-like class imbalance is available.
            ranking = (metrics["accuracy"], metrics["f1"], metrics["recall"])
            if best is None or ranking > best["ranking"]:
                best = {
                    "ranking": ranking,
                    "semantic_weight": float(semantic_weight),
                    "threshold": float(threshold),
                    "metrics": metrics,
                }

    bundle["decision"] = {
        "semantic_weight": best["semantic_weight"],
        "threshold": best["threshold"],
        "objective": "accuracy_then_f1_then_recall",
        "tuned_on": "validation_behavior.jsonl",
    }
    joblib.dump(bundle, MODEL_PATH)

    print("Tuned decision policy on validation data")
    print("Semantic weight:", round(best["semantic_weight"], 4))
    print("Threshold:", round(best["threshold"], 4))
    for name, value in best["metrics"].items():
        print(f"Validation {name}:", round(value, 4))


if __name__ == "__main__":
    main()
