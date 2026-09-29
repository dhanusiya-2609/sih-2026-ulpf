"""
The single event-processing pipeline used by every ingestion path (file
upload, UDP listener, TCP listener). Centralizing this guarantees the same
raw-preservation, parsing, normalization and validation guarantees apply
everywhere, and that one malformed event can never crash the caller.
"""
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from ..models import RawEvent, NormalizedEvent, Source
from ..parsers.registry import registry
from ..normalization import normalize, compute_content_hash, to_schema_dict, validate_schema
from ..vendor_detect import detect_vendor, guess_device_type, is_unknown

logger = logging.getLogger("ulpf.pipeline")


def process_single_event(
    db: Session,
    raw_text: str,
    *,
    source_id: Optional[str] = None,
    collection_method: str = "upload",
    ingestion_job_id: Optional[str] = None,
    peer_address: Optional[str] = None,
    forced_parser_name: Optional[str] = None,
) -> NormalizedEvent:
    """
    Process exactly one event end-to-end. Never raises for malformed/unknown
    input (AC-10) -- worst case the event is stored with normalization_status
    = 'unrecognized' via the generic fallback parser.
    """
    source: Optional[Source] = None
    if source_id:
        source = db.query(Source).filter(Source.source_id == source_id).first()

    raw_event = RawEvent(
        source_id=source_id,
        ingestion_job_id=ingestion_job_id,
        collection_method=collection_method,
        raw_message=raw_text,
        content_hash=compute_content_hash(raw_text),
        peer_address=peer_address,
        ingest_timestamp=datetime.now(timezone.utc),
    )
    db.add(raw_event)
    db.flush()  # obtain raw_event.id without committing

    try:
        parse_result = registry.parse(
            raw_text,
            forced_parser_name=forced_parser_name or (source.parser_name if source else None),
        )
    except Exception as e:  # absolute last-resort guard
        logger.exception("Unexpected pipeline failure during parse")
        from ..parsers.base import ParseResult
        parse_result = ParseResult(
            status="failed", parser_name="pipeline_guard", parser_version="1.0",
            warnings=[f"unexpected pipeline error: {e}"],
        )

    # Vendor: trust what a human registered on the Source; if that is missing
    # or "Unknown", fall back to detecting it from the log content itself.
    vendor = source.vendor if source and not is_unknown(source.vendor) else detect_vendor(raw_text)
    device_type = source.device_type if source and not is_unknown(source.device_type) else None
    if device_type is None and vendor:
        device_type = guess_device_type(vendor, raw_text)

    norm_fields = normalize(
        parse_result,
        source_id=source_id,
        device_name_hint=source.device_name if source else None,
        vendor=vendor,
        device_type=device_type,
        device_mgmt_ip=source.ip_address if source else None,
    )

    normalized_event = NormalizedEvent(raw_event_id=raw_event.id, **norm_fields)
    db.add(normalized_event)
    db.flush()

    # Schema validation pass (does not block storage of the raw event, but is
    # recorded so failures are visible rather than silent).
    doc = to_schema_dict(normalized_event, raw_event, include_raw_message=False)
    errors = validate_schema(doc)
    if errors:
        warn_list = list(normalized_event.warnings or [])
        warn_list.append(f"schema validation issues: {'; '.join(errors[:5])}")
        normalized_event.warnings = warn_list

    if source:
        source.events_received = (source.events_received or 0) + 1
        if normalized_event.normalization_status in ("failed", "unrecognized"):
            source.events_malformed = (source.events_malformed or 0) + 1
        source.last_event_at = datetime.now(timezone.utc)

    return normalized_event
