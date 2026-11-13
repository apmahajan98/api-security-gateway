"""Reusable local ML anomaly-detector adapter."""

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

import joblib
from sentence_transformers import SentenceTransformer

from app.ml.features import TrafficWindow, to_behavior_features

DetectorStatus = Literal["normal", "anomaly"]


@dataclass(frozen=True)
class MLDetectionResult:
    """Stable result contract returned to the gateway decision service."""

    detector: str
    status: DetectorStatus
    score: float
    reason_code: str | None
    model_version: str
    behavior_score: float
    semantic_score: float

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible result for the API and dashboard."""
        return asdict(self)


class MLAnomalyDetector:
    """Load and run the locally trained hybrid anomaly detector.

    The class owns model inference only. It does not know about FastAPI,
    PostgreSQL, UI code, or static security rules.
    """

    detector_name = "ml-anomaly"

    def __init__(
        self,
        model_path: str | Path,
        device: str = "cpu",
        local_files_only: bool = False,
    ) -> None:
        self.model_path = Path(model_path)
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"ML model artifact not found: {self.model_path}. "
                "Run `python -m scripts.train_anomaly_model` first."
            )

        bundle = joblib.load(self.model_path)
        self.model_version = str(bundle.get("model_version", "unknown"))
        self.embedding_model_name = str(bundle["embedding_model"])
        self.embedding_model = SentenceTransformer(
            self.embedding_model_name,
            device=device,
            local_files_only=local_files_only,
        )
        self.behavior_detector = bundle["behavior_detector"]
        self.behavior_detectors = bundle.get("behavior_detectors", {})
        self.semantic_detector = bundle["semantic_detector"]
        self.decision = bundle.get(
            "decision",
            {"semantic_weight": 0.0, "threshold": 0.0},
        )

    def health(self) -> dict[str, str]:
        """Return model metadata for a system-health endpoint."""
        return {
            "status": "loaded",
            "model_version": self.model_version,
            "embedding_model": self.embedding_model_name,
        }

    def analyze(self, window: TrafficWindow) -> MLDetectionResult:
        """Analyze one time-windowed request-behavior summary."""
        behavior_detector = self.behavior_detectors.get(
            window.client_profile,
            self.behavior_detector,
        )
        behavior_features = to_behavior_features(window).reshape(1, -1)
        semantic_embedding = self.embedding_model.encode(
            [window.semantic_summary()],
            normalize_embeddings=True,
        )

        behavior_score = float(behavior_detector.decision_function(behavior_features)[0])
        semantic_score = float(self.semantic_detector.decision_function(semantic_embedding)[0])
        semantic_weight = float(self.decision.get("semantic_weight", 0.0))
        threshold = float(self.decision.get("threshold", 0.0))
        combined_score = behavior_score + semantic_weight * semantic_score
        is_anomaly = combined_score < threshold

        return MLDetectionResult(
            detector=self.detector_name,
            status="anomaly" if is_anomaly else "normal",
            score=round(combined_score, 6),
            reason_code="UNUSUAL_BEHAVIOR" if is_anomaly else None,
            model_version=self.model_version,
            behavior_score=round(behavior_score, 6),
            semantic_score=round(semantic_score, 6),
        )
