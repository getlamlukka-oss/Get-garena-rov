# Root Dockerfile for Garena RoV Academy Auto-Solver v3.0 on Cloud Run
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY garena-bot/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY garena-bot/ /app/
COPY static/ /app/static/

RUN mkdir -p /app/data /app/static

EXPOSE 8080

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080} --workers 1"]
