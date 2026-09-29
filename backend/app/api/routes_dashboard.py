from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import NormalizedEvent, Source, User
from ..auth import get_current_user
from ..ingestion.listeners import stats as listener_stats

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
def dashboard_stats(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    total = db.query(func.count(NormalizedEvent.id)).scalar() or 0

    def count_status(s):
        return db.query(func.count(NormalizedEvent.id)).filter(NormalizedEvent.normalization_status == s).scalar() or 0

    by_vendor = dict(
        db.query(NormalizedEvent.vendor, func.count(NormalizedEvent.id))
        .group_by(NormalizedEvent.vendor).all()
    )
    by_vendor = {(k or "unknown"): v for k, v in by_vendor.items()}

    by_severity = dict(
        db.query(NormalizedEvent.event_severity, func.count(NormalizedEvent.id))
        .group_by(NormalizedEvent.event_severity).all()
    )
    by_severity = {(k or "unknown"): v for k, v in by_severity.items()}

    by_device = dict(
        db.query(NormalizedEvent.device_name, func.count(NormalizedEvent.id))
        .group_by(NormalizedEvent.device_name).all()
    )
    by_device = {(k or "unknown"): v for k, v in by_device.items()}

    sources_total = db.query(func.count(Source.id)).scalar() or 0
    sources_active = db.query(func.count(Source.id)).filter(Source.enabled == True).scalar() or 0  # noqa: E712

    return {
        "total_events": total,
        "normalized_success": count_status("success"),
        "normalized_partial": count_status("partial"),
        "normalized_failed": count_status("failed"),
        "unrecognized": count_status("unrecognized"),
        "events_by_vendor": by_vendor,
        "events_by_severity": by_severity,
        "events_by_device": by_device,
        "sources_total": sources_total,
        "sources_active": sources_active,
        "udp_received": listener_stats.udp_received,
        "udp_malformed": listener_stats.udp_malformed,
        "udp_dropped": listener_stats.udp_dropped,
        "tcp_received": listener_stats.tcp_received,
        "tcp_malformed": listener_stats.tcp_malformed,
    }


@router.get("/trend")
def event_trend(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Hourly event counts for the last 24 buckets seen in the data (SQLite-portable)."""
    rows = (
        db.query(
            func.strftime("%Y-%m-%d %H:00", NormalizedEvent.ingest_timestamp).label("bucket"),
            func.count(NormalizedEvent.id),
        )
        .group_by("bucket")
        .order_by("bucket")
        .all()
    )
    return [{"bucket": b, "count": c} for b, c in rows[-24:]]
