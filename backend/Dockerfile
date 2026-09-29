FROM python:3.12-slim

WORKDIR /app

# System deps kept minimal; psycopg2-binary needs no build toolchain.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY migrations ./migrations
COPY alembic.ini .
COPY docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

# Runtime data directory (SQLite db, raw event storage, uploads, exports)
RUN mkdir -p /data
ENV ULPF_DATA_DIR=/data

EXPOSE 8000 5514/udp 5515

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:8000/api/health || exit 1

ENTRYPOINT ["./docker-entrypoint.sh"]
