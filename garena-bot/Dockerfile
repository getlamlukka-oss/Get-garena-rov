# Multi-stage Dockerfile for Garena RoV Academy Auto-Solver v3.0 on Cloud Run
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app

# Install system dependencies needed for compiling cryptography and curl_cffi wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source files
COPY . .

# Ensure data and static directories exist
RUN mkdir -p /app/data /app/static

EXPOSE 8080

# Run uvicorn on $PORT (Default: 8080 for Cloud Run)
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1"]
