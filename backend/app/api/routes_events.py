from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import NormalizedEvent, RawEvent, User
from ..auth import get_current_user
from ..normalization import to_schema_dict, compute_content_hash
from ..redaction import redact_event_doc, redact_message

router = APIRouter(prefix="/api/events", tags=["events"])


@router.get("")
def search_events(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    vendor: Optional[str] = None,
    device_name: Optional[str] = None,
    device_ip: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    action: Optional[str] = None,
    severity: Optional[str] = None,
    normalization_status: Optional[str] = None,
    event_category: Optional[str] = None,
    ip: Optional[str] = Query(None, description="Match this IP as either source or destination"),
    q: Optional[str] = Query(None, description="Free-text search across message field"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
):
    """
    Server-side filtered, paginated event search. The full table is never
    loaded into the browser (AC-13 / UI requirement H).
    """
    query = db.query(NormalizedEvent)

    if start_time:
        query = query.filter(NormalizedEvent.event_timestamp >= start_time)
    if end_time:
        query = query.filter(NormalizedEvent.event_timestamp <= end_time)
    if vendor:
        query = query.filter(NormalizedEvent.vendor == vendor)
    if device_name:
        query = query.filter(NormalizedEvent.device_name == device_name)
    if device_ip:
        query = query.filter(NormalizedEvent.device_ip == device_ip)
    if source_ip:
        query = query.filter(NormalizedEvent.source_ip == source_ip)
    if destination_ip:
        query = query.filter(NormalizedEvent.destination_ip == destination_ip)
    if protocol:
        query = query.filter(NormalizedEvent.protocol == protocol)
    if action:
        query = query.filter(NormalizedEvent.event_action == action)
    if severity:
        query = query.filter(NormalizedEvent.event_severity == severity)
    if normalization_status:
        query = query.filter(NormalizedEvent.normalization_status == normalization_status)
    if event_category:
        query = query.filter(NormalizedEvent.event_category == event_category)
    if ip:
        query = query.filter(or_(NormalizedEvent.source_ip == ip, NormalizedEvent.destination_ip == ip,
                                  NormalizedEvent.device_ip == ip))
    if q:
        like = f"%{q}%"
        query = query.filter(NormalizedEvent.message.ilike(like))

    total = query.count()
    items = (
        query.order_by(NormalizedEvent.ingest_timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    results = []
    for ne in items:
        results.append({
            "event_id": ne.id, "event_timestamp": ne.event_timestamp.isoformat() if ne.event_timestamp else None,
            "timestamp_uncertain": ne.timestamp_uncertain,
            "ingest_timestamp": ne.ingest_timestamp.isoformat(),
            "vendor": ne.vendor, "device_name": ne.device_name, "device_type": ne.device_type,
            "source_ip": ne.source_ip, "destination_ip": ne.destination_ip,
            "protocol": ne.protocol, "action": ne.event_action, "severity": ne.event_severity,
            "category": ne.event_category, "status": ne.normalization_status,
            "parser_name": ne.parser_name, "message": redact_message(ne.message),
        })

    return {"total": total, "page": page, "page_size": page_size, "items": results}


@router.get("/{event_id}")
def get_event_detail(event_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    ne = db.query(NormalizedEvent).filter(NormalizedEvent.id == event_id).first()
    if not ne:
        raise HTTPException(status_code=404, detail="Event not found")
    raw = db.query(RawEvent).filter(RawEvent.id == ne.raw_event_id).first()
    can_see_raw = user.role in ("admin", "analyst")
    doc = to_schema_dict(ne, raw, include_raw_message=can_see_raw)
    doc = redact_event_doc(doc)
    doc["integrity"] = {
        "content_hash": raw.content_hash,
        "recomputed_hash": compute_content_hash(raw.raw_message),
        "hash_match": raw.content_hash == compute_content_hash(raw.raw_message),
    } if can_see_raw else {
        "content_hash": raw.content_hash,
        "note": "Recomputed-hash verification and raw_message require the 'analyst' role or higher.",
    }
    return doc


@router.get("/{event_id}/raw")
def get_raw_event(event_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """View the complete original log for a normalized event. Restricted to
    analyst/admin roles -- viewers see normalized, redacted data only."""
    if user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Viewing raw log content requires the 'analyst' role or higher")
    ne = db.query(NormalizedEvent).filter(NormalizedEvent.id == event_id).first()
    if not ne:
        raise HTTPException(status_code=404, detail="Event not found")
    raw = db.query(RawEvent).filter(RawEvent.id == ne.raw_event_id).first()
    return {
        "raw_event_id": raw.id, "raw_message": raw.raw_message, "content_hash": raw.content_hash,
        "collection_method": raw.collection_method, "peer_address": raw.peer_address,
        "ingest_timestamp": raw.ingest_timestamp.isoformat(),
        "integrity_verified": raw.content_hash == compute_content_hash(raw.raw_message),
    }
