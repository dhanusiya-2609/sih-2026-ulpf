from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from ..database import get_db
from ..models import TrainingRecord, RawEvent, NormalizedEvent, MappingDefinition, User, AuditLog
from ..schemas import TrainingApprove
from ..auth import get_current_user, require_role
from ..ai_suggest import suggest_mapping
from ..parsers.json_parser import _flatten
import json

router = APIRouter(prefix="/api/training", tags=["training"])


@router.get("/unknown-samples")
def list_unknown_samples(limit: int = 20, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Representative raw samples for events that were unrecognized or only partially parsed."""
    events = (
        db.query(NormalizedEvent)
        .filter(NormalizedEvent.normalization_status.in_(["unrecognized", "failed", "partial"]))
        .order_by(NormalizedEvent.ingest_timestamp.desc())
        .limit(limit)
        .all()
    )
    out = []
    for ne in events:
        raw = db.query(RawEvent).filter(RawEvent.id == ne.raw_event_id).first()
        out.append({
            "normalized_event_id": ne.id, "raw_event_id": raw.id if raw else None,
            "raw_message": raw.raw_message if raw else None,
            "status": ne.normalization_status, "parser_name": ne.parser_name,
            "source_id": ne.source_id, "warnings": ne.warnings,
        })
    return out


@router.post("/suggest/{raw_event_id}")
def suggest_for_sample(raw_event_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Run the (heuristic, offline-by-default) suggestion engine against one raw sample."""
    raw = db.query(RawEvent).filter(RawEvent.id == raw_event_id).first()
    if not raw:
        raise HTTPException(status_code=404, detail="Raw event not found")

    sample_fields: dict = {}
    text = raw.raw_message.strip()
    try:
        if text.startswith("{"):
            sample_fields = _flatten(json.loads(text))
        else:
            import re
            for k, v in re.findall(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)', text):
                sample_fields[k] = v.strip('"')
    except Exception:
        pass

    if not sample_fields:
        sample_fields = {"raw_message": text[:200]}

    suggestions, source = suggest_mapping(sample_fields)

    record = TrainingRecord(
        source_id=raw.source_id, sample_raw_event_id=raw.id,
        suggested_mapping=suggestions, suggestion_source=source, status="pending",
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "training_record_id": record.id,
        "sample_fields": sample_fields,
        "suggested_mapping": suggestions,
        "suggestion_source": source,
        "disclaimer": "Suggestions are advisory only and were not auto-applied. "
                       "Review and approve before they take effect on future events.",
    }


@router.get("/records")
def list_training_records(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    records = db.query(TrainingRecord).order_by(TrainingRecord.created_at.desc()).all()
    return [
        {"id": r.id, "source_id": r.source_id, "sample_raw_event_id": r.sample_raw_event_id,
         "suggested_mapping": r.suggested_mapping, "suggestion_source": r.suggestion_source,
         "final_mapping": r.final_mapping, "status": r.status, "created_at": r.created_at.isoformat()}
        for r in records
    ]


@router.post("/records/{record_id}/approve")
def approve_training_record(record_id: str, payload: TrainingApprove, db: Session = Depends(get_db),
                             user: User = Depends(require_role("analyst"))):
    record = db.query(TrainingRecord).filter(TrainingRecord.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Training record not found")

    record.final_mapping = payload.final_mapping
    record.status = "approved"
    record.reviewed_by = payload.reviewed_by
    record.reviewed_at = datetime.now(timezone.utc)

    mapping = MappingDefinition(
        name=f"approved-mapping-{record.id[:8]}", source_id=record.source_id,
        field_map=payload.final_mapping, status="approved", created_by=payload.reviewed_by,
        approved_at=datetime.now(timezone.utc),
    )
    db.add(mapping)
    db.add(AuditLog(actor=user.username, action="approve_training_mapping", target=record_id))
    db.commit()
    return {"status": "approved", "mapping_id": mapping.id}


@router.post("/records/{record_id}/reject")
def reject_training_record(record_id: str, db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    record = db.query(TrainingRecord).filter(TrainingRecord.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Training record not found")
    record.status = "rejected"
    record.reviewed_by = user.username
    record.reviewed_at = datetime.now(timezone.utc)
    db.commit()
    return {"status": "rejected"}
