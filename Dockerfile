FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip

COPY requirements.txt ./
COPY asice-cli ./asice-cli
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir ./asice-cli

COPY gateway ./gateway
COPY config ./config
COPY docker-entrypoint.sh ./

RUN chmod +x docker-entrypoint.sh

EXPOSE 8088

CMD ["./docker-entrypoint.sh"]
