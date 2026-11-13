# Model artifacts

The trained `*.joblib` artifact is intentionally ignored by Git. A teammate
can recreate it locally from the tracked configuration and synthetic data:

```bash
python -m scripts.generate_traffic
python -m scripts.train_anomaly_model
python -m scripts.tune_anomaly_model
```

The model bundle stores the model version, embedding model name, global and
client-profile behavior detectors, semantic detector, and tuned decision
policy. Do not commit production traffic or sensitive model inputs.
