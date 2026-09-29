"""
Pydantic request/response models, including the formal Universal Event Schema
(also mirrored as JSON Schema in app/event_schema.json for external validation
and for SIEM/data-lake consumers that want a language-neutral contract).
"""
from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, Field


# ---------- Auth ----------
class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


# ---------- Sources ----------
class SourceCreate(BaseModel):
    source_id: str
    device_name: str
    vendor: str
    device_type: str
    ip_address: Optional[str] = None
    input_format: str = "auto"
    collection_method: str = "upload"
    parser_name: Optional[str] = None
    mapping_id: Optional[str] = None
    notes: Optional[str] = None


class SourceUpdate(BaseModel):
    device_name: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    ip_address: Optional[str] = None
    input_format: Optional[str] = None
    collection_method: Optional[str] = None
    parser_name: Optional[str] = None
    mapping_id: Optional[str] = None
    enabled: Optional[bool] = None
    notes: Optional[str] = None


class SourceOut(BaseModel):
    source_id: str
    device_name: str
    vendor: str
    device_type: str
    ip_address: Optional[str]
    input_format: str
    collection_method: str
    parser_name: Optional[str]
    enabled: bool
    events_received: int
    events_malformed: int
    last_event_at: Optional[datetime]

    class Config:
        from_attributes = True


# ---------- Universal Event Schema (nested, matches problem statement) ----------
class EventSourceSchema(BaseModel):
    source_id: Optional[str] = None
    device_name: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    source_ip: Optional[str] = None  # device management IP, distinct from network.source_ip


class EventDetailSchema(BaseModel):
    category: Optional[str] = None
    type: Optional[str] = None
    action: Optional[str] = None
    severity: Optional[str] = None
    outcome: Optional[str] = None


class NetworkSchema(BaseModel):
    transport: Optional[str] = None
    protocol: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None


class NormalizationSchema(BaseModel):
    status: str = "unknown"  # success | partial | failed | unrecognized
    parser_name: Optional[str] = None
    parser_version: Optional[str] = None
    mapping_version: Optional[str] = None
    warnings: list[str] = Field(default_factory=list)
    unparsed_fields: list[str] = Field(default_factory=list)


class RawEventRefSchema(BaseModel):
    raw_event_id: str
    content_hash: Optional[str] = None
    raw_message: Optional[str] = None  # included only in detail views


class NormalizedEventSchema(BaseModel):
    event_id: str
    schema_version: str = "1.0"
    event_timestamp: Optional[str] = None  # ISO 8601, null if undetermined
    event_timestamp_raw: Optional[str] = None
    timestamp_uncertain: bool = False
    ingest_timestamp: str
    source: EventSourceSchema
    event: EventDetailSchema
    network: NetworkSchema
    vendor_fields: dict[str, Any] = Field(default_factory=dict)
    normalization: NormalizationSchema
    raw_event: RawEventRefSchema
    message: Optional[str] = None


# ---------- Ingestion ----------
class IngestResult(BaseModel):
    job_id: str
    filename: Optional[str] = None
    total_events: int
    success_count: int
    partial_count: int
    failed_count: int
    status: str


# ---------- Parser / Mapping ----------
class ParserOut(BaseModel):
    name: str
    version: str
    format_family: str
    description: Optional[str]
    is_builtin: bool
    is_active: bool
    events_parsed: int
    events_failed: int

    class Config:
        from_attributes = True


class ParserTestRequest(BaseModel):
    parser_name: Optional[str] = None  # if omitted, auto-detect
    sample_text: str


class MappingCreate(BaseModel):
    name: str
    vendor: Optional[str] = None
    source_id: Optional[str] = None
    field_map: dict[str, str]


class TrainingApprove(BaseModel):
    final_mapping: dict[str, str]
    reviewed_by: Optional[str] = "admin"


# ---------- Alerts ----------
class AlertCreate(BaseModel):
    rule_name: str
    field: str
    operator: str  # eq, contains, gt, lt
    value: str
    severity: str = "medium"


# ---------- Dashboard ----------
class DashboardStats(BaseModel):
    total_events: int
    normalized_success: int
    normalized_partial: int
    normalized_failed: int
    unrecognized: int
    events_by_vendor: dict[str, int]
    events_by_severity: dict[str, int]
    events_by_device: dict[str, int]
    sources_total: int
    sources_active: int
    udp_received: int
    udp_malformed: int
    tcp_received: int
