import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, JSON, Index
)
from sqlalchemy.orm import relationship

from .database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=_uuid)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="admin")  # admin | analyst | viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=_now)


class Source(Base):
    """A registered log source / device."""
    __tablename__ = "sources"
    id = Column(String, primary_key=True, default=_uuid)
    source_id = Column(String, unique=True, nullable=False, index=True)  # human-facing slug
    device_name = Column(String, nullable=False)
    vendor = Column(String, nullable=False, index=True)
    device_type = Column(String, nullable=False)  # firewall, router, switch, server...
    ip_address = Column(String, index=True)
    input_format = Column(String, default="auto")  # syslog, json, csv, xml, cef, leef, auto
    collection_method = Column(String, default="upload")  # upload, udp, tcp
    parser_name = Column(String, nullable=True)  # pinned parser, else auto-detect
    mapping_id = Column(String, ForeignKey("mapping_definitions.id"), nullable=True)
    enabled = Column(Boolean, default=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=_now)
    updated_at = Column(DateTime, default=_now, onupdate=_now)

    # health counters (best-effort operational visibility, not guaranteed-accurate for UDP)
    events_received = Column(Integer, default=0)
    events_malformed = Column(Integer, default=0)
    last_event_at = Column(DateTime, nullable=True)


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"
    id = Column(String, primary_key=True, default=_uuid)
    source_id = Column(String, ForeignKey("sources.source_id"), nullable=True, index=True)
    job_type = Column(String)  # file_upload, bulk_upload, udp_stream, tcp_stream
    filename = Column(String, nullable=True)
    status = Column(String, default="pending")  # pending, running, completed, failed
    total_events = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    failed_count = Column(Integer, default=0)
    partial_count = Column(Integer, default=0)
    started_at = Column(DateTime, default=_now)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)


class RawEvent(Base):
    """Immutable, lossless copy of the original event exactly as received."""
    __tablename__ = "raw_events"
    id = Column(String, primary_key=True, default=_uuid)  # raw_event_id
    source_id = Column(String, ForeignKey("sources.source_id"), nullable=True, index=True)
    ingestion_job_id = Column(String, ForeignKey("ingestion_jobs.id"), nullable=True)
    collection_method = Column(String)  # upload, udp, tcp
    original_format_hint = Column(String, nullable=True)
    raw_message = Column(Text, nullable=False)  # complete, unmodified original event
    content_hash = Column(String, index=True)  # sha256 of raw_message for integrity
    peer_address = Column(String, nullable=True)  # remote IP for live-collected events
    ingest_timestamp = Column(DateTime, default=_now, index=True)

    normalized_event = relationship("NormalizedEvent", back_populates="raw_event", uselist=False)


class NormalizedEvent(Base):
    """Structured, schema-validated representation derived from a RawEvent."""
    __tablename__ = "normalized_events"
    id = Column(String, primary_key=True, default=_uuid)  # event_id
    raw_event_id = Column(String, ForeignKey("raw_events.id"), nullable=False, index=True)
    schema_version = Column(String, default="1.0")

    event_timestamp = Column(DateTime, nullable=True, index=True)
    event_timestamp_raw = Column(String, nullable=True)  # original text if unparseable
    timestamp_uncertain = Column(Boolean, default=False)
    ingest_timestamp = Column(DateTime, default=_now, index=True)

    source_id = Column(String, ForeignKey("sources.source_id"), nullable=True, index=True)
    device_name = Column(String, nullable=True, index=True)
    vendor = Column(String, nullable=True, index=True)
    device_type = Column(String, nullable=True)
    device_ip = Column(String, nullable=True, index=True)

    event_category = Column(String, nullable=True, index=True)
    event_type = Column(String, nullable=True)
    event_action = Column(String, nullable=True, index=True)
    event_severity = Column(String, nullable=True, index=True)
    event_outcome = Column(String, nullable=True)

    transport = Column(String, nullable=True)
    protocol = Column(String, nullable=True, index=True)
    source_ip = Column(String, nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    destination_ip = Column(String, nullable=True, index=True)
    destination_port = Column(Integer, nullable=True)

    message = Column(Text, nullable=True)
    vendor_fields = Column(JSON, default=dict)  # preserved unmapped/vendor-specific fields

    normalization_status = Column(String, default="unknown", index=True)  # success | partial | failed | unrecognized
    parser_name = Column(String, nullable=True, index=True)
    parser_version = Column(String, nullable=True)
    mapping_version = Column(String, nullable=True)
    warnings = Column(JSON, default=list)
    unparsed_fields = Column(JSON, default=list)

    raw_event = relationship("RawEvent", back_populates="normalized_event")


Index("ix_norm_event_time_severity", NormalizedEvent.event_timestamp, NormalizedEvent.event_severity)


class ParserDefinition(Base):
    __tablename__ = "parser_definitions"
    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, unique=True, nullable=False)
    version = Column(String, default="1.0")
    format_family = Column(String)  # syslog, json, csv, xml, cef, leef, kv, generic
    description = Column(Text, nullable=True)
    is_builtin = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    events_parsed = Column(Integer, default=0)
    events_failed = Column(Integer, default=0)
    created_at = Column(DateTime, default=_now)


class MappingDefinition(Base):
    __tablename__ = "mapping_definitions"
    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    vendor = Column(String, nullable=True)
    source_id = Column(String, nullable=True)  # optional: scoped to one source
    version = Column(String, default="1.0")
    field_map = Column(JSON, default=dict)  # {source_field: target_schema_path}
    status = Column(String, default="draft")  # draft, approved, active
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=_now)
    approved_at = Column(DateTime, nullable=True)


class TrainingRecord(Base):
    """A human (optionally AI-assisted) parser onboarding session for unknown logs."""
    __tablename__ = "training_records"
    id = Column(String, primary_key=True, default=_uuid)
    source_id = Column(String, nullable=True)
    sample_raw_event_id = Column(String, ForeignKey("raw_events.id"), nullable=True)
    suggested_mapping = Column(JSON, default=dict)  # AI/heuristic suggestion, advisory only
    suggestion_source = Column(String, default="heuristic")  # heuristic | local_llm | none
    final_mapping = Column(JSON, default=dict)  # human-approved mapping
    status = Column(String, default="pending")  # pending, approved, rejected
    reviewed_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=_now)
    reviewed_at = Column(DateTime, nullable=True)


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(String, primary_key=True, default=_uuid)
    rule_name = Column(String, nullable=False)
    condition = Column(JSON, default=dict)  # simple rule spec, e.g. field/op/value
    severity = Column(String, default="medium")
    is_active = Column(Boolean, default=True)
    triggered_count = Column(Integer, default=0)
    last_triggered_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_now)


class AlertEvent(Base):
    """A record of a specific alert firing against a specific normalized event."""
    __tablename__ = "alert_events"
    id = Column(String, primary_key=True, default=_uuid)
    alert_id = Column(String, ForeignKey("alerts.id"), index=True)
    normalized_event_id = Column(String, ForeignKey("normalized_events.id"), index=True)
    triggered_at = Column(DateTime, default=_now)


class IntegrationConfig(Base):
    __tablename__ = "integration_configs"
    id = Column(String, primary_key=True, default=_uuid)
    name = Column(String, nullable=False)
    integration_type = Column(String)  # webhook, file_drop, syslog_forward
    config = Column(JSON, default=dict)  # endpoint URL, format, auth ref, etc.
    is_active = Column(Boolean, default=True)
    last_run_at = Column(DateTime, nullable=True)
    last_status = Column(String, nullable=True)
    created_at = Column(DateTime, default=_now)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=_uuid)
    actor = Column(String, nullable=True)
    action = Column(String, nullable=False)
    target = Column(String, nullable=True)
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=_now, index=True)
