"""
Configuration management for ULPF.

All configuration is sourced from environment variables (with sane defaults
for local/offline development) so the application can be reconfigured at
deploy time without code changes, per the 12-factor / Docker requirements.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # backend/
DATA_DIR = Path(os.environ.get("ULPF_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)


class Settings:
    # --- Core ---
    APP_NAME: str = "Universal Log Pre-processing Framework"
    SCHEMA_VERSION: str = "1.0"
    ENV: str = os.environ.get("ULPF_ENV", "development")

    # --- Database ---
    # SQLite by default (prototype / single-instance / air-gapped mode).
    # Set ULPF_DATABASE_URL to a PostgreSQL DSN for production deployments,
    # e.g. postgresql+psycopg2://user:pass@host:5432/ulpf
    DATABASE_URL: str = os.environ.get(
        "ULPF_DATABASE_URL", f"sqlite:///{(DATA_DIR / 'ulpf.db').as_posix()}"
    )

    # --- Storage ---
    RAW_STORAGE_DIR: Path = Path(
        os.environ.get("ULPF_RAW_STORAGE_DIR", DATA_DIR / "raw_events")
    )
    UPLOAD_TMP_DIR: Path = Path(
        os.environ.get("ULPF_UPLOAD_TMP_DIR", DATA_DIR / "uploads")
    )
    EXPORT_DIR: Path = Path(os.environ.get("ULPF_EXPORT_DIR", DATA_DIR / "exports"))

    # --- Auth ---
    JWT_SECRET: str = os.environ.get("ULPF_JWT_SECRET", "dev-only-change-me-in-prod")
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = int(os.environ.get("ULPF_JWT_EXPIRE_MINUTES", "480"))
    DEFAULT_ADMIN_USER: str = os.environ.get("ULPF_ADMIN_USER", "admin")
    DEFAULT_ADMIN_PASSWORD: str = os.environ.get("ULPF_ADMIN_PASSWORD", "admin123")

    # --- Ingestion listeners ---
    SYSLOG_UDP_HOST: str = os.environ.get("ULPF_SYSLOG_UDP_HOST", "0.0.0.0")
    SYSLOG_UDP_PORT: int = int(os.environ.get("ULPF_SYSLOG_UDP_PORT", "5514"))
    SYSLOG_TCP_HOST: str = os.environ.get("ULPF_SYSLOG_TCP_HOST", "0.0.0.0")
    SYSLOG_TCP_PORT: int = int(os.environ.get("ULPF_SYSLOG_TCP_PORT", "5515"))
    ENABLE_UDP_LISTENER: bool = os.environ.get("ULPF_ENABLE_UDP", "true").lower() == "true"
    ENABLE_TCP_LISTENER: bool = os.environ.get("ULPF_ENABLE_TCP", "true").lower() == "true"

    # --- Misc ---
    MAX_UPLOAD_MB: int = int(os.environ.get("ULPF_MAX_UPLOAD_MB", "50"))
    RETENTION_DAYS: int = int(os.environ.get("ULPF_RETENTION_DAYS", "90"))

    # --- Redaction ---
    # Comma-separated vendor_fields / kv key names whose values are masked in
    # API responses and exports (raw_event.raw_message is never altered --
    # redaction is a presentation-layer control, not data mutation; the
    # unredacted original remains available to admin/analyst roles via the
    # raw-event endpoint, per the "restricted raw log access" requirement).
    REDACT_FIELDS: list[str] = [
        f.strip().lower() for f in os.environ.get(
            "ULPF_REDACT_FIELDS", "password,passwd,pwd,secret,token,api_key,authorization"
        ).split(",") if f.strip()
    ]


settings = Settings()

settings.RAW_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
settings.UPLOAD_TMP_DIR.mkdir(parents=True, exist_ok=True)
settings.EXPORT_DIR.mkdir(parents=True, exist_ok=True)
