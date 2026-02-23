# Multi-stage build for EPS Discount Integration Service
# Stage 1: Builder
FROM python:3.12-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.12-slim

LABEL maintainer="EPS Discount Service"
LABEL description="EPS Discount Integration API Service"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    SERVER_HOST=0.0.0.0 \
    SERVER_PORT=8000 \
    LOG_DIR=/app/logs

# Create app directory
WORKDIR /app

# Create logs directory
RUN mkdir -p /app/logs && chmod 755 /app/logs

# Install runtime utilities (ping)
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Copy application files (credentials come from docker-compose env_file, not baked into image)
COPY eps_discount_integration.py .
COPY requirements.txt .

# Health check (use container port 8001)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8001/api/health', timeout=5)" || exit 1

# Expose port
EXPOSE 8001

# Run the application
CMD ["python", "-m", "uvicorn", "eps_discount_integration:app", \
     "--host", "0.0.0.0", "--port", "8001", "--workers", "2"]
