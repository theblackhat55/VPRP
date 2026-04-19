# ============================================================
# VPRP Platform — Multi-Stage Dockerfile
# ============================================================

# ── Base Stage ───────────────────────────────────────────
FROM python:3.11-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl libpq-dev && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -r -m -s /bin/bash appuser
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /data/uploads /data/reports /data/archives /data/logs && \
    chown -R appuser:appuser /data /app

# ── Development Stage ────────────────────────────────────
FROM base AS development

COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY .streamlit/ ./.streamlit/

USER appuser
EXPOSE 8501

CMD ["streamlit", "run", "app/main.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--server.maxUploadSize=200", \
     "--server.runOnSave=true", \
     "--browser.gatherUsageStats=false"]

# ── Production Stage ─────────────────────────────────────
FROM base AS production

COPY app/ ./app/
COPY .streamlit/ ./.streamlit/

USER appuser
EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

CMD ["streamlit", "run", "app/main.py", \
     "--server.port=8501", \
     "--server.address=0.0.0.0", \
     "--server.headless=true", \
     "--server.maxUploadSize=200", \
     "--browser.gatherUsageStats=false"]
