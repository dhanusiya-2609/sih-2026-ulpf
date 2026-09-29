from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, AuditLog
from ..schemas import IngestResult
from ..auth import get_current_user
from ..config import settings
from ..ingestion.file_ingest import ingest_text_blob

router = APIRouter(prefix="/api/ingest", tags=["ingestion"])

MAX_BYTES = settings.MAX_UPLOAD_MB * 1024 * 1024


async def _read_limited(f: UploadFile) -> str:
    content = await f.read()
    if len(content) > MAX_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds max upload size of {settings.MAX_UPLOAD_MB} MB")
    return content.decode("utf-8", errors="replace")


@router.post("/upload", response_model=IngestResult)
async def upload_single(
    file: UploadFile = File(...),
    source_id: str | None = None,
    parser_name: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    text = await _read_limited(file)
    job = ingest_text_blob(db, text, filename=file.filename, source_id=source_id,
                            job_type="file_upload", forced_parser_name=parser_name)
    db.add(AuditLog(actor=user.username, action="upload_file", target=file.filename,
                     details={"job_id": job.id, "events": job.total_events}))
    db.commit()
    return IngestResult(job_id=job.id, filename=job.filename, total_events=job.total_events,
                         success_count=job.success_count, partial_count=job.partial_count,
                         failed_count=job.failed_count, status=job.status)


@router.post("/bulk-upload", response_model=list[IngestResult])
async def upload_bulk(
    files: list[UploadFile] = File(...),
    source_id: str | None = None,
    parser_name: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    results = []
    for file in files:
        text = await _read_limited(file)
        job = ingest_text_blob(db, text, filename=file.filename, source_id=source_id,
                                job_type="bulk_upload", forced_parser_name=parser_name)
        results.append(IngestResult(job_id=job.id, filename=job.filename, total_events=job.total_events,
                                     success_count=job.success_count, partial_count=job.partial_count,
                                     failed_count=job.failed_count, status=job.status))
    db.add(AuditLog(actor=user.username, action="bulk_upload", target=f"{len(files)} files",
                     details={"job_ids": [r.job_id for r in results]}))
    db.commit()
    return results


@router.get("/jobs")
def list_jobs(limit: int = 50, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    from ..models import IngestionJob
    jobs = db.query(IngestionJob).order_by(IngestionJob.started_at.desc()).limit(limit).all()
    return [
        {
            "id": j.id, "source_id": j.source_id, "job_type": j.job_type, "filename": j.filename,
            "status": j.status, "total_events": j.total_events, "success_count": j.success_count,
            "partial_count": j.partial_count, "failed_count": j.failed_count,
            "started_at": j.started_at.isoformat() if j.started_at else None,
            "completed_at": j.completed_at.isoformat() if j.completed_at else None,
            "error_message": j.error_message,
        }
        for j in jobs
    ]
