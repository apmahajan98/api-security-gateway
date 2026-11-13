# ML training and reproducibility

## Current approach

The detector is a hybrid, CPU-only anomaly detector:

1. `all-MiniLM-L6-v2` creates embeddings from a sanitized route/profile
   summary.
2. Numeric behavior features describe traffic in a time window.
3. Isolation Forest models learn normal behavior.
4. Separate behavior baselines are trained for consumer, employee, and service
   clients.
5. Validation data tunes the semantic-score weight and decision threshold.
6. The evaluation data is held out until the final report.

The Hugging Face model is a pretrained feature extractor. The project-specific
training happens when Isolation Forest is fitted on normal traffic windows.

## Rebuild the model

From the repository root:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m scripts.generate_traffic
python -m scripts.train_anomaly_model
python -m scripts.tune_anomaly_model
python -m scripts.evaluate_anomaly_model
```

The first model run needs internet access to download the public Hugging Face
model. Later runs can use the local cache with `HF_HUB_OFFLINE=1`.

## What to record for every experiment

- Git commit
- Model version
- Dataset generator version and seed
- Number of training, validation, and evaluation windows
- Feature schema
- Embedding model
- Isolation Forest parameters
- Threshold and semantic weight
- Accuracy, precision, recall, F1, false-positive rate, and false-negative rate
- CPU, Python, and dependency versions

Do not tune the final evaluation set. Use validation data for threshold and
hyperparameter decisions, then report the untouched evaluation result.

## Retraining later

When better authorized or sanitized data is available:

1. Add a versioned dataset or update the generator.
2. Update `configs/ml_config.json` and increment `model_version`.
3. Regenerate or import training, validation, and evaluation data.
4. Train and tune from the repository root.
5. Compare against the previous model using the same held-out test set.
6. Record the results before replacing the model artifact.
