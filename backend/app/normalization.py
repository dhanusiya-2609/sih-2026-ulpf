"""
Normalization engine.

Takes a ParseResult (parser-specific intermediate fields) plus known source
metadata and produces a validated dict matching event_schema.json, ready to
persist as a NormalizedEvent row and/or export as a NormalizedEventSchema.

Design rules enforced here (per problem statement):
- Never fabricate values for fields that could not be determined -> use None.
- Distinguish event_timestamp (best-effort parsed) from event_timestamp_raw
  (verbatim original text) and ingest_timestamp (always the processing time).
- A device's management IP (source.source_ip) is kept distinct from a
  connection's source IP (network.source_ip).
"""
import hashlib
import json
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Optional

from jsonschema import Draft7Validator

from .parsers.base import ParseResult

SCHEMA_PATH = Path(__file__).resolve().parent / "event_schema.json"
_EVENT_SCHEMA = json.loads(SCHEMA_PATH.read_text())
_VALIDATOR = Draft7Validator(_EVENT_SCHEMA)

MAPPING_VERSION = "1.0"

SEVERITY_ALIASES = {
    "emerg": "emergency", "emergency": "emergency",
    "alert": "alert",
    "crit": "critical", "critical": "critical",
    "err": "error", "error": "error",
    "warn": "warning", "warning": "warning",
    "notice": "notice",
    "info": "informational", "informational": "informational",
    "debug": "debug",
    "high": "high", "medium": "medium", "low": "low",
}


def _map_numeric_severity(raw: str) -> Optional[str]:
    """CEF/LEEF use a 0-10 numeric severity scale (0-3 low, 4-6 medium,
    7-8 high, 9-10 very-high/critical), distinct from syslog's 0-7 PRI
    scale which is handled separately via PRI_SEVERITY_MAP. Only applied
    when the raw value is purely numeric."""
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return None
    if n <= 3:
        return "low"
    if n <= 6:
        return "medium"
    if n <= 8:
        return "high"
    return "critical"

TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%d",
    "%b %d %H:%M:%S", "%d/%b/%Y:%H:%M:%S",
]


def compute_content_hash(raw_message: str) -> str:
    return hashlib.sha256(raw_message.encode("utf-8", errors="replace")).hexdigest()


def try_parse_timestamp(raw: Optional[str]) -> tuple[Optional[datetime], bool]:
    """Best-effort timestamp parse. Returns (datetime_or_None, uncertain_flag).
    Never raises; never guesses a value it can't support."""
    if not raw:
        return None, True
    raw = raw.strip()
    try:
        dt = parsedate_to_datetime(raw)
        if dt:
            return dt, False
    except Exception:
        pass
    for fmt in TS_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                if "%Y" not in fmt:
                    # e.g. "Oct 11 22:14:15" has no year -> assume current year,
                    # flagged uncertain since the source did not confirm it
                    dt = dt.replace(year=datetime.now(timezone.utc).year, tzinfo=timezone.utc)
                    return dt, True
                dt = dt.replace(tzinfo=timezone.utc)
            return dt, False
        except ValueError:
            continue
    return None, True


def _coerce_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def normalize(
    parse_result: ParseResult,
    *,
    source_id: Optional[str] = None,
    device_name_hint: Optional[str] = None,
    vendor: Optional[str] = None,
    device_type: Optional[str] = None,
    device_mgmt_ip: Optional[str] = None,
) -> dict:
    """Produce a dict of fields suitable for constructing a NormalizedEvent row."""
    f = parse_result.fields
    warnings = list(parse_result.warnings)

    event_ts, uncertain = try_parse_timestamp(parse_result.event_timestamp_raw)
    if parse_result.event_timestamp_raw and event_ts is None:
        warnings.append("event timestamp text present but could not be confidently parsed")

    severity_raw = f.get("severity")
    if severity_raw is not None:
        alias = SEVERITY_ALIASES.get(str(severity_raw).lower())
        if alias:
            severity = alias
        else:
            numeric = _map_numeric_severity(severity_raw)
            severity = numeric if numeric is not None else severity_raw
    else:
        severity = None

    status = parse_result.status
    # Downgrade success->partial if nothing meaningful was identified beyond
    # the envelope, so the UI never overstates confidence. Any of: network
    # 5-tuple, an action, or a recognized event category/type counts as
    # meaningful (e.g. an interface up/down event has no network tuple but
    # is still a fully-understood, correctly classified event).
    has_meaning = any(f.get(k) for k in (
        "source_ip", "destination_ip", "protocol", "action", "event_category", "event_type"
    ))
    if status == "success" and not has_meaning:
        status = "partial"
        warnings.append("normalization marked partial: no network, action, or category/type fields identified")

    normalized = {
        "schema_version": "1.0",
        "event_timestamp": event_ts,
        "event_timestamp_raw": parse_result.event_timestamp_raw,
        "timestamp_uncertain": uncertain,
        "source_id": source_id,
        "device_name": f.get("device_name") or device_name_hint,
        "vendor": vendor,
        "device_type": device_type,
        "device_ip": device_mgmt_ip,
        "event_category": f.get("event_category"),
        "event_type": f.get("event_type"),
        "event_action": f.get("action"),
        "event_severity": severity,
        "event_outcome": f.get("outcome"),
        "transport": f.get("protocol"),
        "protocol": f.get("protocol"),
        "source_ip": f.get("source_ip"),
        "source_port": _coerce_int(f.get("source_port")),
        "destination_ip": f.get("destination_ip"),
        "destination_port": _coerce_int(f.get("destination_port")),
        "message": f.get("message"),
        "vendor_fields": parse_result.vendor_fields,
        "normalization_status": status,
        "parser_name": parse_result.parser_name,
        "parser_version": parse_result.parser_version,
        "mapping_version": MAPPING_VERSION,
        "warnings": warnings,
        "unparsed_fields": parse_result.unparsed_fields,
    }
    return normalized


def to_schema_dict(normalized_event, raw_event, include_raw_message: bool = True) -> dict:
    """Build a dict matching event_schema.json from ORM objects, for API/export."""
    doc = {
        "event_id": normalized_event.id,
        "schema_version": normalized_event.schema_version,
        "event_timestamp": normalized_event.event_timestamp.isoformat() if normalized_event.event_timestamp else None,
        "event_timestamp_raw": normalized_event.event_timestamp_raw,
        "timestamp_uncertain": normalized_event.timestamp_uncertain,
        "ingest_timestamp": normalized_event.ingest_timestamp.isoformat(),
        "source": {
            "source_id": normalized_event.source_id,
            "device_name": normalized_event.device_name,
            "vendor": normalized_event.vendor,
            "device_type": normalized_event.device_type,
            "source_ip": normalized_event.device_ip,
        },
        "event": {
            "category": normalized_event.event_category,
            "type": normalized_event.event_type,
            "action": normalized_event.event_action,
            "severity": normalized_event.event_severity,
            "outcome": normalized_event.event_outcome,
        },
        "network": {
            "transport": normalized_event.transport,
            "protocol": normalized_event.protocol,
            "source_ip": normalized_event.source_ip,
            "source_port": normalized_event.source_port,
            "destination_ip": normalized_event.destination_ip,
            "destination_port": normalized_event.destination_port,
        },
        "vendor_fields": normalized_event.vendor_fields or {},
        "message": normalized_event.message,
        "normalization": {
            "status": normalized_event.normalization_status,
            "parser_name": normalized_event.parser_name,
            "parser_version": normalized_event.parser_version,
            "mapping_version": normalized_event.mapping_version,
            "warnings": normalized_event.warnings or [],
            "unparsed_fields": normalized_event.unparsed_fields or [],
        },
        "raw_event": {
            "raw_event_id": raw_event.id,
            "content_hash": raw_event.content_hash,
            "raw_message": raw_event.raw_message if include_raw_message else None,
        },
    }
    return doc


def validate_schema(doc: dict) -> list[str]:
    """Return a list of human-readable validation errors (empty if valid)."""
    errors = sorted(_VALIDATOR.iter_errors(doc), key=lambda e: e.path)
    return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]
