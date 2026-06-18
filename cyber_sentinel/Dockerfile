# ============================================================
# Cyber Sentinel - Multi-Stage Production Dockerfile
# Optimized for FastAPI + Streamlit deployment
# ============================================================

FROM python:3.11-slim AS base

# System-level dependencies for ML libraries and telethon
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /cyber_sentinel

# Copy and install Python dependencies first (Docker layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy full application source
COPY . .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash sentinel && \
    chown -R sentinel:sentinel /cyber_sentinel
USER sentinel

# Expose ports
EXPOSE 8080 8501

# Health check endpoint for container orchestration
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default startup command (override in docker-compose)
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
