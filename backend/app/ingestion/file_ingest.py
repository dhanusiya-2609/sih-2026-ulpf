import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ..models import IngestionJob
from .pipeline import process_single_event


def split_into_events(text: str) -> list[str]:
    """
    Split raw file content into individual event strings.
    - A single top-level JSON array -> one event per array element.
    - Otherwise: one event per non-empty line (covers syslog batches, JSONL,
      CSV-with-header-as-context-per-line, CEF/LEEF-per-line).
    A whole-file XML document with no newlines between events is treated as
    a single event, since XML records in this prototype are one-per-line or
    one-per-file (documented limitation).
    """
    stripped = text.strip()
    if stripped.startswith("["):
        try:
            data = json.loads(stripped)
            if isinstance(data, list):
                return [json.dumps(item) for item in data]
        except Exception:
            pass
    lines = [l for l in text.splitlines() if l.strip()]
    if lines:
        return lines
    return [text] if text.strip() else []


def ingest_text_blob(
    db: Session,
    text: str,
    *,
    filename: Optional[str] = None,
    source_id: Optional[str] = None,
    job_type: str = "file_upload",
    forced_parser_name: Optional[str] = None,
) -> IngestionJob:
    job = IngestionJob(
        source_id=source_id, job_type=job_type, filename=filename,
        status="running", started_at=datetime.now(timezone.utc),
    )
    db.add(job)
    db.flush()

    events = split_into_events(text)
    job.total_events = len(events)
    success = partial = failed = 0

    for raw in events:
        try:
            ne = process_single_event(
                db, raw, source_id=source_id, collection_method="upload",
                ingestion_job_id=job.id, forced_parser_name=forced_parser_name,
            )
            if ne.normalization_status == "success":
                success += 1
            elif ne.normalization_status == "partial":
                partial += 1
            else:
                failed += 1
        except Exception as e:
            # Should not happen (pipeline guards internally) but keep the job
            # loop alive regardless, per AC-10.
            failed += 1
            job.error_message = f"{job.error_message or ''}\nunexpected error on one event: {e}".strip()

    job.success_count = success
    job.partial_count = partial
    job.failed_count = failed
    job.status = "completed"
    job.completed_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(job)
    return job
