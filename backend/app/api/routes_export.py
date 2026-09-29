import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import NormalizedEvent, RawEvent, User
from ..auth import get_current_user
from ..normalization import to_schema_dict
from ..redaction import redact_event_doc

router = APIRouter(prefix="/api/export", tags=["export"])


def _filtered_query(db: Session, vendor, severity, normalization_status, start_time, end_time):
    query = db.query(NormalizedEvent)
    if vendor:
        query = query.filter(NormalizedEvent.vendor == vendor)
    if severity:
        query = query.filter(NormalizedEvent.event_severity == severity)
    if normalization_status:
        query = query.filter(NormalizedEvent.normalization_status == normalization_status)
    if start_time:
        query = query.filter(NormalizedEvent.event_timestamp >= start_time)
    if end_time:
        query = query.filter(NormalizedEvent.event_timestamp <= end_time)
    return query.order_by(NormalizedEvent.ingest_timestamp.desc())


@router.get("/json")
def export_json(
    db: Session = Depends(get_db), user: User = Depends(get_current_user),
    vendor: Optional[str] = None, severity: Optional[str] = None,
    normalization_status: Optional[str] = None,
    start_time: Optional[datetime] = None, end_time: Optional[datetime] = None,
    limit: int = Query(1000, le=20000),
):
    can_see_raw = user.role in ("admin", "analyst")
    events = _filtered_query(db, vendor, severity, normalization_status, start_time, end_time).limit(limit).all()
    docs = []
    for ne in events:
        raw = db.query(RawEvent).filter(RawEvent.id == ne.raw_event_id).first()
        docs.append(redact_event_doc(to_schema_dict(ne, raw, include_raw_message=can_see_raw)))

    def gen():
        yield json.dumps({"schema_version": "1.0", "exported_count": len(docs), "events": docs}, indent=2)

    return StreamingResponse(gen(), media_type="application/json",
                              headers={"Content-Disposition": "attachment; filename=ulpf_export.json"})


@router.get("/jsonl")
def export_jsonl(
    db: Session = Depends(get_db), user: User = Depends(get_current_user),
    vendor: Optional[str] = None, severity: Optional[str] = None,
    normalization_status: Optional[str] = None,
    start_time: Optional[datetime] = None, end_time: Optional[datetime] = None,
    limit: int = Query(5000, le=100000),
):
    can_see_raw = user.role in ("admin", "analyst")
    events = _filtered_query(db, vendor, severity, normalization_status, start_time, end_time).limit(limit).all()

    def gen():
        for ne in events:
            raw = db.query(RawEvent).filter(RawEvent.id == ne.raw_event_id).first()
            doc = redact_event_doc(to_schema_dict(ne, raw, include_raw_message=can_see_raw))
            yield json.dumps(doc) + "\n"

    return StreamingResponse(gen(), media_type="application/x-ndjson",
                              headers={"Content-Disposition": "attachment; filename=ulpf_export.jsonl"})
