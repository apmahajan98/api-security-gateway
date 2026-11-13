"""Detector adapters used by the gateway inspection pipeline."""

from app.detectors.ml_anomaly import MLAnomalyDetector, MLDetectionResult

__all__ = ["MLAnomalyDetector", "MLDetectionResult"]
