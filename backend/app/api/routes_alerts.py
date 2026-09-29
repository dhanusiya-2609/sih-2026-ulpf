from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Alert, AlertEvent, NormalizedEvent, User, AuditLog
from ..schemas import AlertCreate
from ..auth import get_current_user, require_role

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

OPS = {"eq": lambda a, b: str(a) == str(b),
       "contains": lambda a, b: str(b).lower() in str(a or "").lower(),
       "gt": lambda a, b: _num(a) is not None and _num(a) > _num(b),
       "lt": lambda a, b: _num(a) is not None and _num(a) < _num(b)}


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


FIELD_MAP = {
    "severity": "event_severity", "action": "event_action", "protocol": "protocol",
    "source_ip": "source_ip", "destination_ip": "destination_ip", "vendor": "vendor",
    "category": "event_category", "status": "normalization_status",
}


@router.get("")
def list_alerts(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return [
        {"id": a.id, "rule_name": a.rule_name, "condition": a.condition, "severity": a.severity,
         "is_active": a.is_active, "triggered_count": a.triggered_count,
         "last_triggered_at": a.last_triggered_at.isoformat() if a.last_triggered_at else None}
        for a in db.query(Alert).order_by(Alert.created_at.desc()).all()
    ]


@router.post("")
def create_alert(payload: AlertCreate, db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    if payload.field not in FIELD_MAP:
        raise HTTPException(status_code=400, detail=f"Unsupported field. Supported: {list(FIELD_MAP)}")
    if payload.operator not in OPS:
        raise HTTPException(status_code=400, detail=f"Unsupported operator. Supported: {list(OPS)}")
    alert = Alert(
        rule_name=payload.rule_name, severity=payload.severity,
        condition={"field": payload.field, "operator": payload.operator, "value": payload.value},
    )
    db.add(alert)
    db.add(AuditLog(actor=user.username, action="create_alert", target=payload.rule_name))
    db.commit()
    db.refresh(alert)
    return {"id": alert.id, "status": "created"}


@router.delete("/{alert_id}")
def delete_alert(alert_id: str, db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    db.delete(alert)
    db.commit()
    return {"status": "deleted"}


@router.post("/evaluate")
def evaluate_alerts(limit: int = 200, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """
    Rule-based evaluation only (no ML / predictive detection claimed).
    Runs active rules against the most recent normalized events and records
    any matches. Intended to be called periodically or on demand.
    """
    alerts = db.query(Alert).filter(Alert.is_active == True).all()  # noqa: E712
    if not alerts:
        return {"evaluated_events": 0, "matches": 0}

    events = db.query(NormalizedEvent).order_by(NormalizedEvent.ingest_timestamp.desc()).limit(limit).all()
    matches = 0
    for alert in alerts:
        cond = alert.condition or {}
        attr = FIELD_MAP.get(cond.get("field"))
        op = OPS.get(cond.get("operator"))
        if not attr or not op:
            continue
        for ne in events:
            value = getattr(ne, attr, None)
            try:
                if op(value, cond.get("value")):
                    db.add(AlertEvent(alert_id=alert.id, normalized_event_id=ne.id))
                    alert.triggered_count = (alert.triggered_count or 0) + 1
                    alert.last_triggered_at = datetime.now(timezone.utc)
                    matches += 1
            except Exception:
                continue
    db.commit()
    return {"evaluated_events": len(events), "matches": matches}


@router.get("/events")
def list_alert_events(limit: int = 100, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = db.query(AlertEvent).order_by(AlertEvent.triggered_at.desc()).limit(limit).all()
    out = []
    for r in rows:
        alert = db.query(Alert).filter(Alert.id == r.alert_id).first()
        out.append({
            "id": r.id, "alert_id": r.alert_id, "rule_name": alert.rule_name if alert else None,
            "normalized_event_id": r.normalized_event_id, "triggered_at": r.triggered_at.isoformat(),
        })
    return out
