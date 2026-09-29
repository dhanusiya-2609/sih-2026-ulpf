import re

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Source, User, AuditLog
from ..schemas import SourceCreate, SourceUpdate, SourceOut
from ..auth import get_current_user, require_role
from ..config import settings
from ..ingestion.file_ingest import ingest_text_blob, split_into_events
from ..vendor_detect import detect_vendor_for_lines, guess_device_type, UNKNOWN

router = APIRouter(prefix="/api/sources", tags=["sources"])

MAX_BYTES = settings.MAX_UPLOAD_MB * 1024 * 1024


@router.get("", response_model=list[SourceOut])
def list_sources(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Source).order_by(Source.created_at.desc()).all()


@router.post("", response_model=SourceOut)
def create_source(payload: SourceCreate, db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    if db.query(Source).filter(Source.source_id == payload.source_id).first():
        raise HTTPException(status_code=409, detail="A source with this source_id already exists")
    src = Source(**payload.model_dump())
    db.add(src)
    db.add(AuditLog(actor=user.username, action="create_source", target=payload.source_id))
    db.commit()
    db.refresh(src)
    return src


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "source"


def _unique_source_id(db: Session, base_slug: str, taken: set[str]) -> str:
    candidate = base_slug
    n = 2
    while db.query(Source).filter(Source.source_id == candidate).first() or candidate in taken:
        candidate = f"{base_slug}-{n}"
        n += 1
    return candidate


@router.post("/upload")
async def upload_log_files_as_sources(
    files: list[UploadFile] = File(...),
    vendor: str | None = None,
    device_type: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_role("analyst")),
):
    """
    Bulk onboarding shortcut: upload one or more raw log files directly and
    a Source is auto-registered for each one (source_id/device_name derived
    from the filename), then the file's events are ingested against that
    new source immediately -- so you don't have to hand-fill the "Add
    source" form once per device before you can upload its log.

    `vendor`/`device_type` apply to every file in this batch if provided;
    leave blank and edit the created source afterwards if devices differ.
    Auto-created sources use `input_format=auto` (format auto-detection),
    so mixed formats in one batch are handled correctly.
    """
    taken_ids: set[str] = set()
    results = []

    for f in files:
        content = await f.read()
        if len(content) > MAX_BYTES:
            results.append({
                "filename": f.filename, "status": "rejected",
                "error": f"File exceeds max upload size of {settings.MAX_UPLOAD_MB} MB",
            })
            continue
        text = content.decode("utf-8", errors="replace")

        stem = re.sub(r"\.[^.]+$", "", f.filename or "source")
        base_slug = _slugify(stem)
        source_id = _unique_source_id(db, base_slug, taken_ids)
        taken_ids.add(source_id)

        # Vendor/device type: use what the caller supplied for the batch,
        # otherwise detect them from the file's content (majority vote over
        # its lines) and filename. Falls back to "Unknown" only when no
        # distinctive vendor signature is present.
        detected_vendor = detect_vendor_for_lines(split_into_events(text))
        final_vendor = vendor or detected_vendor or UNKNOWN
        final_type = device_type or guess_device_type(final_vendor, f"{stem} {text[:4000]}")

        src = Source(
            source_id=source_id,
            device_name=stem,
            vendor=final_vendor,
            device_type=final_type,
            input_format="auto",
            collection_method="upload",
            notes=(f"Vendor auto-detected from log content: {detected_vendor}"
                   if (not vendor and detected_vendor) else None),
        )
        db.add(src)
        db.flush()

        job = ingest_text_blob(db, text, filename=f.filename, source_id=source_id, job_type="file_upload")

        db.add(AuditLog(actor=user.username, action="upload_create_source", target=source_id,
                         details={"filename": f.filename, "events": job.total_events}))

        results.append({
            "filename": f.filename, "status": "created", "source_id": source_id,
            "vendor": final_vendor, "device_type": final_type,
            "total_events": job.total_events, "success_count": job.success_count,
            "partial_count": job.partial_count, "failed_count": job.failed_count,
        })

    db.commit()
    return {"results": results}


@router.get("/{source_id}", response_model=SourceOut)
def get_source(source_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    src = db.query(Source).filter(Source.source_id == source_id).first()
    if not src:
        raise HTTPException(status_code=404, detail="Source not found")
    return src


@router.put("/{source_id}", response_model=SourceOut)
def update_source(source_id: str, payload: SourceUpdate, db: Session = Depends(get_db),
                   user: User = Depends(require_role("analyst"))):
    src = db.query(Source).filter(Source.source_id == source_id).first()
    if not src:
        raise HTTPException(status_code=404, detail="Source not found")
    for k, v in payload.model_dump(exclude_unset=True).items():
        setattr(src, k, v)
    db.add(AuditLog(actor=user.username, action="update_source", target=source_id))
    db.commit()
    db.refresh(src)
    return src


@router.delete("/{source_id}")
def delete_source(source_id: str, db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    src = db.query(Source).filter(Source.source_id == source_id).first()
    if not src:
        raise HTTPException(status_code=404, detail="Source not found")
    db.delete(src)
    db.add(AuditLog(actor=user.username, action="delete_source", target=source_id))
    db.commit()
    return {"status": "deleted", "source_id": source_id}
