FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/root/.cache/huggingface

WORKDIR /app

COPY pyproject.toml .
COPY app ./app
COPY configs ./configs
COPY data ./data
COPY models ./models
COPY scripts ./scripts

# Windows checkouts can convert shell scripts to CRLF. Normalize the startup
# script inside the Linux image so /bin/sh does not parse the trailing \r as an
# option (which otherwise causes: "set: Illegal option -").
RUN sed -i 's/\r$//' scripts/docker_model_init.sh \
    && chmod +x scripts/docker_model_init.sh

# Use the CPU-only PyTorch wheel so Docker does not download CUDA libraries.
RUN python -m pip install --no-cache-dir \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    "torch==2.5.1+cpu"
RUN python -m pip install --no-cache-dir .

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
