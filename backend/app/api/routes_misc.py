from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import IntegrationConfig, AuditLog, User
from ..auth import get_current_user, require_role
from ..config import settings

router = APIRouter(prefix="/api", tags=["misc"])


# ---------- Integrations ----------
@router.get("/integrations")
def list_integrations(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return [
        {"id": i.id, "name": i.name, "type": i.integration_type, "config": i.config,
         "is_active": i.is_active, "last_run_at": i.last_run_at.isoformat() if i.last_run_at else None,
         "last_status": i.last_status}
        for i in db.query(IntegrationConfig).all()
    ]


@router.post("/integrations")
def create_integration(payload: dict, db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    """
    Register an outbound integration adapter. Supported, testable types in
    this prototype: 'webhook' (HTTP POST of new normalized events) and
    'file_drop' (periodic JSONL export to a local directory for pickup by
    an external SIEM/data-lake importer). Claims are limited to what is
    actually implemented; no specific commercial SIEM is claimed compatible
    unless a dedicated, tested adapter exists.
    """
    name = payload.get("name")
    itype = payload.get("integration_type")
    if itype not in ("webhook", "file_drop"):
        raise HTTPException(status_code=400, detail="integration_type must be 'webhook' or 'file_drop'")
    integ = IntegrationConfig(name=name, integration_type=itype, config=payload.get("config", {}))
    db.add(integ)
    db.add(AuditLog(actor=user.username, action="create_integration", target=name))
    db.commit()
    db.refresh(integ)
    return {"id": integ.id, "status": "created"}


# ---------- Settings ----------
@router.get("/settings")
def get_settings(user: User = Depends(get_current_user)):
    return {
        "retention_days": settings.RETENTION_DAYS,
        "max_upload_mb": settings.MAX_UPLOAD_MB,
        "syslog_udp_port": settings.SYSLOG_UDP_PORT,
        "syslog_tcp_port": settings.SYSLOG_TCP_PORT,
        "udp_listener_enabled": settings.ENABLE_UDP_LISTENER,
        "tcp_listener_enabled": settings.ENABLE_TCP_LISTENER,
        "offline_mode": True,
        "environment": settings.ENV,
    }


# ---------- Audit log ----------
@router.get("/audit-logs")
def list_audit_logs(limit: int = 100, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return [
        {"id": r.id, "actor": r.actor, "action": r.action, "target": r.target,
         "details": r.details, "created_at": r.created_at.isoformat()}
        for r in rows
    ]


# ---------- Health ----------
@router.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    return {"status": "ok" if db_ok else "degraded", "database": db_ok,
            "time": datetime.now(timezone.utc).isoformat()}


# ---------- Schema ----------
@router.get("/schema/event")
def get_event_schema():
    """Public (no-auth) endpoint serving the versioned universal event JSON Schema,
    so external consumers/validators can fetch it without a token."""
    from fastapi.responses import FileResponse
    from ..normalization import SCHEMA_PATH
    return FileResponse(str(SCHEMA_PATH), media_type="application/json")
