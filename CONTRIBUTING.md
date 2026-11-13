# Team contribution guide

## First-time setup

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
cp .env.example .env
python -m pytest -q
```

The Hugging Face model is downloaded the first time the ML pipeline runs. It
runs locally on CPU; no API key or GPU is required.

## Ownership boundaries

- `app/main.py`: gateway transport and rule-based inspection.
- `app/detectors/`: detector adapters and ML decision interface.
- `app/ml/`: shared ML features and traffic representations.
- `configs/`, `data/`, `scripts/`, `docs/ML_TRAINING.md`: ML experiments,
  datasets, configuration, and reproducibility records.
- Database work should add persistence behind a separate repository/service
  boundary and must not log raw credentials, tokens, or request bodies.
- `app/static/`: dashboard UI; keep it independent from detector internals.

Prefer focused branches and pull requests. Before opening a pull request, run:

```bash
ruff check .
ruff format --check .
python -m pytest -q
```

## ML changes

Do not commit `models/*.joblib`, real traffic, secrets, or raw sensitive
payloads. Rebuild the artifact from tracked inputs:

```bash
python -m scripts.generate_traffic
python -m scripts.train_anomaly_model
python -m scripts.tune_anomaly_model
python -m scripts.evaluate_anomaly_model
```

If the feature schema, generator, model, or threshold changes, increment
`model_version` in `configs/ml_config.json` and record the new evaluation
metrics in the pull request. See `docs/ML_TRAINING.md` for the full procedure.
