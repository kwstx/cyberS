# Use a scalable multi-stage build
FROM python:3.10-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml .

# Install dependencies into a virtual environment
RUN pip install --upgrade pip && \
    pip install .

# Runner stage
FROM python:3.10-slim

WORKDIR /app

# Copy python dependencies from builder
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy project files
COPY . .

# Default to running the API (can be overridden by k8s command/args)
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
