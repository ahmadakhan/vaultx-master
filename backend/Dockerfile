FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Only copy dependency files first for better caching
COPY requirements.txt .

# Build wheels for all deps
RUN pip install --upgrade pip wheel \
    && pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# ---- Runtime: minimal image with just what we need ----
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Runtime libs for Postgres, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -u 10001 -m appuser

WORKDIR /app

# Install Python deps from prebuilt wheels
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Install gunicorn for production worker management
RUN pip install --no-cache-dir "gunicorn>=23.0.0" "uvicorn>=0.32.0"

# Copy application code
COPY . .

# Ensure writable key directory if you mount secrets there
RUN mkdir -p /etc/vaultx/keys /var/vaultx/storage && chown -R appuser:appuser /etc/vaultx /var/vaultx /app

USER appuser

EXPOSE 8000

CMD ["gunicorn", "app.main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "--timeout", "60", "--graceful-timeout", "30"]
