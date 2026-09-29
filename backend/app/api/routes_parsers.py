import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import ParserDefinition, MappingDefinition, User, AuditLog
from ..schemas import ParserTestRequest, MappingCreate
from ..auth import get_current_user, require_role
from ..parsers.registry import registry
from ..normalization import normalize

router = APIRouter(prefix="/api/parsers", tags=["parsers"])


@router.get("")
def list_parsers(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    # Registry is the source of truth for capability; ParserDefinition rows
    # (seeded at startup) carry usage stats and active/inactive state.
    defs = {d.name: d for d in db.query(ParserDefinition).all()}
    out = []
    for p in registry.list_parsers():
        d = defs.get(p.name)
        out.append({
            "name": p.name, "version": p.version, "format_family": p.format_family,
            "is_builtin": True,
            "is_active": d.is_active if d else True,
            "events_parsed": d.events_parsed if d else 0,
            "events_failed": d.events_failed if d else 0,
            "description": (d.description if d else None) or f"{p.format_family.upper()} parser",
        })
    return out


@router.post("/test")
def test_parser(payload: ParserTestRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Test a parser (or auto-detection) against a sample log WITHOUT storing anything."""
    result = registry.parse(payload.sample_text, forced_parser_name=payload.parser_name)
    normalized = normalize(result)
    normalized_out = dict(normalized)
    normalized_out["event_timestamp"] = (
        normalized["event_timestamp"].isoformat() if normalized["event_timestamp"] else None
    )
    return {
        "parser_used": result.parser_name,
        "status": result.status,
        "extracted_fields": result.fields,
        "vendor_fields": result.vendor_fields,
        "warnings": result.warnings,
        "unparsed_fields": result.unparsed_fields,
        "normalized_preview": normalized_out,
    }


@router.get("/export")
def export_parser_configs(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    mappings = db.query(MappingDefinition).all()
    return {
        "schema_version": "1.0",
        "mappings": [
            {"name": m.name, "vendor": m.vendor, "source_id": m.source_id,
             "version": m.version, "field_map": m.field_map, "status": m.status}
            for m in mappings
        ],
    }


@router.post("/import")
def import_parser_configs(payload: dict, db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    imported = 0
    for m in payload.get("mappings", []):
        md = MappingDefinition(
            name=m["name"], vendor=m.get("vendor"), source_id=m.get("source_id"),
            version=m.get("version", "1.0"), field_map=m.get("field_map", {}),
            status=m.get("status", "draft"),
        )
        db.add(md)
        imported += 1
    db.add(AuditLog(actor=user.username, action="import_mappings", details={"count": imported}))
    db.commit()
    return {"imported": imported}


@router.get("/mappings")
def list_mappings(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return [
        {"id": m.id, "name": m.name, "vendor": m.vendor, "source_id": m.source_id,
         "version": m.version, "field_map": m.field_map, "status": m.status}
        for m in db.query(MappingDefinition).order_by(MappingDefinition.created_at.desc()).all()
    ]


@router.post("/mappings")
def create_mapping(payload: MappingCreate, db: Session = Depends(get_db), user: User = Depends(require_role("analyst"))):
    md = MappingDefinition(name=payload.name, vendor=payload.vendor, source_id=payload.source_id,
                            field_map=payload.field_map, status="approved")
    db.add(md)
    db.add(AuditLog(actor=user.username, action="create_mapping", target=payload.name))
    db.commit()
    db.refresh(md)
    return {"id": md.id, "status": "created"}
