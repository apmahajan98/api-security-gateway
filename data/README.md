# Synthetic traffic data

These JSONL files are controlled, synthetic traffic windows for model
development. They do not represent production traffic and contain no real
credentials, tokens, or personal data.

- `normal_behavior.jsonl`: normal windows used for unsupervised training.
- `validation_behavior.jsonl`: labeled data used only to tune the decision
  threshold and semantic-score weight.
- `evaluation_behavior.jsonl`: labeled held-out data used only for final
  evaluation.

Regenerate them deterministically with:

```bash
python -m scripts.generate_traffic
```

The generator uses a fixed seed. If the generator or feature schema changes,
record a new model version and rerun the complete training pipeline.
