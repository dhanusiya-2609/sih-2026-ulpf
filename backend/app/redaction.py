"""
Configurable, presentation-layer redaction.

This never touches stored data: RawEvent.raw_message is preserved verbatim
forever (see normalization.py docstring / AC-08). Redaction is applied only
when building an API response or export document, and only masks
vendor_fields keys (and a couple of well-known message patterns) that match
the configured sensitive-field list (settings.REDACT_FIELDS).

Raw log content itself (raw_event.raw_message) is additionally
access-restricted by role rather than redacted: viewer-role callers never
receive it at all (see routes_events.get_event_detail /
get_raw_event), while admin/analyst roles can retrieve the untouched
original for investigation.
"""
import re
from typing import Any

from .config import settings

MASK = "***REDACTED***"
_KV_PATTERN_CACHE: dict[str, re.Pattern] = {}


def _kv_pattern(field: str) -> re.Pattern:
    if field not in _KV_PATTERN_CACHE:
        _KV_PATTERN_CACHE[field] = re.compile(
            rf"(?i)\b({re.escape(field)})\s*=\s*(\"[^\"]*\"|\S+)"
        )
    return _KV_PATTERN_CACHE[field]


def redact_vendor_fields(vendor_fields: dict[str, Any]) -> dict[str, Any]:
    if not vendor_fields:
        return vendor_fields
    out = {}
    for k, v in vendor_fields.items():
        if str(k).strip().lower() in settings.REDACT_FIELDS:
            out[k] = MASK
        else:
            out[k] = v
    return out


def redact_message(message: str | None) -> str | None:
    """Mask key=value occurrences of sensitive field names inside free-text
    messages (e.g. a captured 'password=hunter2' fragment), independent of
    whether that field was also pulled out into vendor_fields."""
    if not message:
        return message
    redacted = message
    for field in settings.REDACT_FIELDS:
        redacted = _kv_pattern(field).sub(rf"\1={MASK}", redacted)
    return redacted


def redact_event_doc(doc: dict) -> dict:
    """Apply redaction to a full universal-event-schema dict (as produced by
    normalization.to_schema_dict), returning a new dict. Safe to call
    unconditionally; a no-op if REDACT_FIELDS is empty."""
    if not settings.REDACT_FIELDS:
        return doc
    doc = dict(doc)
    doc["vendor_fields"] = redact_vendor_fields(doc.get("vendor_fields") or {})
    doc["message"] = redact_message(doc.get("message"))
    return doc
