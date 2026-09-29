# Evaluation Checklist

Status legend: **DONE (tested)** = automated test exists and passes.
**DONE (verified)** = manually exercised and confirmed working in this
session, but not covered by an automated test. **PARTIAL** = implemented
with a documented gap. **NOT DONE** = not implemented, stated plainly.

This document is written to be checked against the code, not taken on
faith — every "DONE (tested)" item has a corresponding test in
`backend/tests/`, runnable with `python3 -m pytest tests/ -v` (66 passed at
time of writing).

## Vendor / device-type detection

| Requirement | Status | Evidence |
|---|---|---|
| Vendor populated automatically, not left "Unknown" | DONE (tested) | `app/vendor_detect.py` — content-based detection (CEF/LEEF header, Cisco `%FACILITY-SEVERITY-MNEMONIC`, FortiGate `devid=FG.../logid=`, Linux daemon tags), majority-voted across a file's lines so one corrupted line can't flip the result; wired into both the shared ingestion pipeline (`process_single_event`) and bulk source upload. `test_vendor_detection.py` (13 tests) includes one parametrized test per real sample log confirming the exact detected vendor and device type |
| Device type inferred, not just vendor | DONE (tested) | `guess_device_type()` — vendor-default plus Cisco switch/router disambiguation from mnemonic/filename hints (`SPANTREE`/`catalyst` -> switch, `OSPF`/`rtr` -> router); same test file |
| Never fabricates a vendor with no signature | DONE (tested) | `test_no_signature_returns_none_not_a_guess` — falls back to "Unknown" rather than guessing |

## Ingestion

| Requirement | Status | Evidence |
|---|---|---|
| Single file upload | DONE (tested) | `test_ac01_single_file_upload_accepted` |
| Bulk / multi-file upload | DONE (tested) | `test_ac02_bulk_upload_multiple_files` |
| Bulk-create sources directly from log files (no manual form-per-device) | DONE (tested) | `test_bulk_source_upload_creates_sources_and_ingests` — `POST /api/sources/upload`: each uploaded file auto-registers a Source (name from filename, dedup'd on collision) and ingests its events in the same call |
| Live UDP syslog collection | DONE (tested + verified) | `test_listeners.py::test_udp_protocol_*` (unit-level, real code path); additionally sent actual UDP datagrams via a Python socket to a running server during development and confirmed the event was stored and normalized (Cisco ASA-style deny line correctly downgraded to `partial` since its `src outside:ip/port` format isn't matched by the connection-tuple regex — an honest result, not a crash) |
| Live TCP syslog collection | DONE (tested + verified) | `test_listeners.py::test_tcp_handler_*`; manually verified with a real TCP socket send (Linux auth-failure line, correctly extracted `source_ip`) |
| Mixed-format batch in one upload | DONE (tested) | `test_ac05_multi_format_batch_file` (JSON + CEF + LEEF + kv-ish lines in one file) |
| Malformed input never crashes the service | DONE (tested) | `test_ac10_malformed_upload_does_not_crash_service`; also `test_registry_never_raises_on_garbage` at the parser level |
| Unrecognized events preserved, clearly marked | DONE (tested) | `test_ac11_unrecognized_events_are_preserved_and_marked` |

## Parsing & normalization

| Requirement | Status | Evidence |
|---|---|---|
| Syslog (RFC3164-style) | DONE (tested) | `test_syslog_parser_*` |
| JSON | DONE (tested) | `test_json_parser_*` |
| CSV | DONE (tested) | `test_csv_parser_*` |
| XML | DONE (tested) | `test_xml_parser_*` |
| CEF | DONE (tested) | `test_cef_parser` |
| LEEF | DONE (tested) | `test_leef_parser` |
| Generic key=value (Fortinet-style) | DONE (tested) | `test_kv_parser_fortinet_style` |
| Generic fallback (never fails) | DONE (tested) | `test_generic_fallback_never_fails` |
| Auto-detection by confidence | DONE (tested) | `test_registry_auto_detects_json`, `test_registry_auto_detects_cef` |
| Cross-vendor field-name consistency (src/srcip/src_ip -> one field) | DONE (tested) | `test_normalization_consistency.py::test_cross_vendor_field_mapping_consistency` — same connection expressed in 4 different formats, asserted to normalize identically |
| Severity-scale reconciliation (syslog PRI vs CEF 0-10) | DONE (tested) | `test_severity_scales_normalize_to_common_words` |
| Distinguish event time / raw time text / ingest time | DONE (tested) | `to_schema_dict` always emits all three; exercised throughout `test_api.py`, `test_integrity.py` |
| Versioned, schema-validated common event format | DONE (tested) | `event_schema.json` (JSON Schema draft-07) + `validate_schema()` called on every normalize in `pipeline.py`; warnings surfaced, not silently dropped |
| Honest confidence (never overclaim `success`) | DONE (tested) | normalization downgrade logic in `normalize()`; exercised implicitly by the 27/36-success ratio on real sample logs (see below) |
| New parser addable without touching core pipeline | DONE (verified) | by construction — adding a parser is one new file + one line in `registry.py`; not separately unit-tested as a "plugin" mechanism per se |

## Storage & integrity

| Requirement | Status | Evidence |
|---|---|---|
| Raw event preserved byte-for-byte | DONE (tested) | `test_raw_message_preserved_verbatim_after_upload` |
| Content hash for tamper/corruption detection | DONE (tested) | `test_content_hash_deterministic`, `test_content_hash_changes_with_content`; recomputed (not just stored) on every detail-view read |
| Raw and normalized linked, not merged | DONE (tested) | `test_normalized_event_traces_to_raw_event` |
| Duplicate events not silently deduplicated away | DONE (tested) | `test_duplicate_events_preserved_as_separate_records` |
| Database migrations (not just `create_all`) | DONE (verified) | Alembic wired (`backend/migrations/`), initial revision generated and applied (`alembic upgrade head` produces all 13 tables), `alembic check` reports no drift against current models |

## API & search

| Requirement | Status | Evidence |
|---|---|---|
| Server-side filtered, paginated search | DONE (tested) | `test_ac13_search_and_filter_by_supported_fields` |
| Event detail view (normalized + raw side by side) | DONE (tested) | `test_normalized_event_traces_to_raw_event`, plus manual UI verification |
| JSON export | DONE (tested) | `test_ac14_json_and_jsonl_export_valid` |
| JSONL streaming export | DONE (tested) | same test |
| Parser test endpoint (dry-run, no storage) | DONE (verified) | manually exercised via curl during development; not separately asserted in pytest (low risk — same registry code path already covered by parser unit tests) |
| Dashboard statistics reflect real data | DONE (tested) | `test_ac12_dashboard_stats_reflect_real_data` |

## AI-assisted parser onboarding

| Requirement | Status | Evidence |
|---|---|---|
| Suggest field mapping for unknown formats | DONE (tested) | `test_ac15_parser_onboarding_save_and_reuse_mapping` |
| Suggestions advisory only, human approval required | DONE (verified by design) | `TrainingRecord.status` starts `pending`; nothing reads `suggested_mapping` for live parsing, only `MappingDefinition` rows created via the explicit `/approve` endpoint are |
| Fully offline, no paid API required | DONE (verified) | `ai_suggest.py` heuristic uses only `difflib`/regex from the standard library; the optional local-LLM hook is disabled unless an env var is explicitly set, and even then is an unimplemented, documented extension point that safely falls back |

## Security

| Requirement | Status | Evidence |
|---|---|---|
| Authentication (token-based) | DONE (tested) | `test_login_success`, `test_login_wrong_password`, `test_unauthenticated_request_rejected` |
| Role-based access control | PARTIAL (tested where applied) | 3 roles enforced on destructive operations (source/alert delete, integration creation, mapping approval) and on raw-log access (`test_rbac_redaction.py`); not applied to every single read endpoint — documented in README as "where practical" per spec wording |
| Configurable redaction of sensitive fields | DONE (tested) | `test_redaction_masks_sensitive_vendor_field`, `test_redaction_masks_password_in_message_text`; raw stored data is never altered by this — presentation-layer only |
| Restricted raw-log access | DONE (tested) | `test_viewer_cannot_see_raw_message_but_analyst_can` |
| Audit log of configuration changes | DONE (verified) | `AuditLog` rows written on login, source/mapping/alert/integration/user changes, uploads; visible on the Audit Log page — not separately asserted in pytest |
| No path traversal via uploaded filenames | DONE (verified) | filenames are stored only as metadata strings, never used to construct filesystem paths (uploads are processed in-memory) |

## UI

| Requirement | Status | Evidence |
|---|---|---|
| Dashboard | DONE (verified) | Bootstrap 5.3 + Chart.js console; all pages confirmed returning HTTP 200 and wired to real API calls; see `app/static/pages/` |
| Light theme by default, dark theme toggle | DONE (verified) | `app/static/js/theme.js` applies `data-bs-theme` before paint (no flash), persisted in `localStorage`; theme tokens defined for both in `app/static/css/theme.css` |
| Real data visualizations (not just tables) | DONE (verified) | Dashboard renders 4 live Chart.js charts (normalization-outcome doughnut, ingestion-trend line, vendor bar, device bar) fed by real `/api/dashboard/stats` and `/api/dashboard/trend` data — confirmed end-to-end with all 5 sample logs ingested (36 events, correct per-vendor/per-device counts) |
| Offline/air-gapped frontend | DONE (verified) | Bootstrap, Bootstrap Icons, and Chart.js are bundled locally under `app/static/vendor/` (no CDN); icon classes spot-checked against the bundled CSS |
| Event explorer with filters | DONE (verified) | same |
| Source management + bulk log-file upload | DONE (tested) | same as ingestion table above |
| Parser testing UI | DONE (verified) | same |
| Onboarding/training UI | DONE (verified) | same |
| Alerts UI | DONE (verified) | same |
| Export UI | DONE (verified) | same |
| Settings / audit log | DONE (verified) | same |
| No page-render/browser-screenshot verification | NOT DONE | no headless browser available in the authoring sandbox; verified via HTTP status checks, a Node.js syntax check of every inline `<script>` block, an icon-class existence check against the bundled CSS, and careful manual review — not a rendered screenshot — stated plainly as a gap |

## Deployment

| Requirement | Status | Evidence |
|---|---|---|
| Dockerfile | DONE (written, not build-tested) | no Docker daemon available in the authoring sandbox; the underlying commands (`pip install -r requirements.txt`, `alembic upgrade head`, `uvicorn ...`) were run directly on the host and verified working in the exact sequence the entrypoint script performs |
| Docker Compose | DONE (written, not build-tested) | same caveat |
| Works fully offline / air-gapped | DONE (verified) | no external network calls anywhere in the backend; frontend uses system font stacks only, no CDN dependency |
| SQLite default, PostgreSQL via config | DONE (verified) | `ULPF_DATABASE_URL` swap, SQLAlchemy-abstracted; only SQLite path was actually exercised in this session (no Postgres instance available in the sandbox) |

## Sample data & real-world plausibility

| Requirement | Status | Evidence |
|---|---|---|
| 5 vendor-representative sample logs | DONE (verified) | `sample_logs/` — Cisco IOS, Cisco Catalyst, Palo Alto (CEF), Fortinet (native kv), Linux server; each clearly labeled synthetic, RFC 5737/private IP ranges only |
| Uploaded and inspected end-to-end | DONE (verified) | actually uploaded all 5 during this session: 27/36 lines fully normalized, 7 honestly marked `partial` (interface/config events with no network tuple), 2 correctly flagged `unrecognized` (the intentionally corrupted lines) |

## Testing summary

66 automated tests across 7 files, all passing at time of writing:
`test_parsers.py` (17), `test_api.py` (17), `test_integrity.py` (5),
`test_listeners.py` (4), `test_normalization_consistency.py` (2),
`test_rbac_redaction.py` (8), `test_vendor_detection.py` (13). Run with
`python3 -m pytest tests/ -v` from `backend/`.
