#!/bin/sh
set -eu

MODEL_PATH=/app/models/anomaly_detector.joblib

if [ "${FORCE_RETRAIN:-0}" != "1" ] && [ -f "$MODEL_PATH" ]; then
    echo "Existing ML model found at $MODEL_PATH; skipping training."
    exit 0
fi

echo "Building the local CPU anomaly model..."
python -m scripts.generate_traffic
python -m scripts.train_anomaly_model
python -m scripts.tune_anomaly_model
python -m scripts.evaluate_anomaly_model

test -f "$MODEL_PATH"
echo "ML model is ready at $MODEL_PATH"
