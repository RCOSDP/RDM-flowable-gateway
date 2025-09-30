#!/bin/bash
set -e

echo "Initializing database..."
python -m gateway.init_db

echo "Starting uvicorn..."
exec uvicorn gateway.main:app \
    --host 0.0.0.0 --port 8088 \
    --log-config /app/config/logging.yaml
