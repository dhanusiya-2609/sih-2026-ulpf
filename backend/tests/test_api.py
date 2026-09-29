import io
import json

import pytest


def test_login_success(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password(client):
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_unauthenticated_request_rejected(client):
    resp = client.get("/api/events")
    assert resp.status_code == 401


def test_source_crud(client, auth_headers):
    create = client.post("/api/sources", json={
        "source_id": "test-src-1", "device_name": "TestDevice", "vendor": "TestVendor",
        "device_type": "firewall", "ip_address": "1.2.3.4",
    }, headers=auth_headers)
    assert create.status_code == 200

    listing = client.get("/api/sources", headers=auth_headers)
    assert any(s["source_id"] == "test-src-1" for s in listing.json())

    update = client.put("/api/sources/test-src-1", json={"enabled": False}, headers=auth_headers)
    assert update.status_code == 200
    assert update.json()["enabled"] is False

    delete = client.delete("/api/sources/test-src-1", headers=auth_headers)
    assert delete.status_code == 200


def test_duplicate_source_id_rejected(client, auth_headers):
    payload = {"source_id": "dup-src", "device_name": "D", "vendor": "V", "device_type": "router"}
    r1 = client.post("/api/sources", json=payload, headers=auth_headers)
    assert r1.status_code == 200
    r2 = client.post("/api/sources", json=payload, headers=auth_headers)
    assert r2.status_code == 409


def test_ac01_single_file_upload_accepted(client, auth_headers):
    files = {"file": ("a.log", io.BytesIO(b'{"src_ip":"1.1.1.1","action":"allow"}'), "text/plain")}
    resp = client.post("/api/ingest/upload", files=files, headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"


def test_ac02_bulk_upload_multiple_files(client, auth_headers):
    files = [
        ("files", ("a.log", io.BytesIO(b'{"src_ip":"1.1.1.1","action":"allow"}'), "text/plain")),
        ("files", ("b.log", io.BytesIO(b'{"src_ip":"2.2.2.2","action":"deny"}'), "text/plain")),
    ]
    resp = client.post("/api/ingest/bulk-upload", files=files, headers=auth_headers)
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 2
    assert all(r["status"] == "completed" for r in results)


def test_ac05_multi_format_batch_file(client, auth_headers):
    """A single upload with multiple lines of different formats (as would
    occur in a bulk-collected batch); each line is treated as one event."""
    lines = [
        '{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","action":"allow"}',
        "src_ip=10.0.0.3,dst_ip=10.0.0.4,action=deny",  # CSV-ish w/ header expected separately; treated standalone
        "CEF:0|Vendor|Product|1.0|100|Test|5|src=10.0.0.5 dst=10.0.0.6",
        "LEEF:2.0|Fortinet|FortiGate|6.0|1000|src=10.0.0.7\tdst=10.0.0.8",
    ]
    files = {"file": ("mixed.log", io.BytesIO("\n".join(lines).encode()), "text/plain")}
    resp = client.post("/api/ingest/upload", files=files, headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_events"] == 4
    assert body["failed_count"] == 0  # nothing should hard-fail; worst case unrecognized


def test_ac10_malformed_upload_does_not_crash_service(client, auth_headers):
    garbage = "\x00\x01\x02 not a log line {{{ ]]] ===="
    files = {"file": ("bad.log", io.BytesIO(garbage.encode()), "text/plain")}
    resp = client.post("/api/ingest/upload", files=files, headers=auth_headers)
    assert resp.status_code == 200  # service stayed up and responded

    # Service must still be responsive after malformed input
    health = client.get("/api/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"


def test_ac11_unrecognized_events_are_preserved_and_marked(client, auth_headers):
    garbage = "completely unstructured free text with no known pattern"
    files = {"file": ("unknown.log", io.BytesIO(garbage.encode()), "text/plain")}
    client.post("/api/ingest/upload", files=files, headers=auth_headers)
    search = client.get("/api/events", params={"normalization_status": "unrecognized", "page_size": 5},
                         headers=auth_headers)
    items = search.json()["items"]
    assert len(items) >= 1
    assert items[0]["status"] == "unrecognized"


def test_ac12_dashboard_stats_reflect_real_data(client, auth_headers):
    files = {"file": ("x.log", io.BytesIO(b'{"src_ip":"5.5.5.5","action":"allow"}'), "text/plain")}
    client.post("/api/ingest/upload", files=files, headers=auth_headers)
    stats = client.get("/api/dashboard/stats", headers=auth_headers).json()
    assert stats["total_events"] >= 1
    assert isinstance(stats["events_by_vendor"], dict)


def test_ac13_search_and_filter_by_supported_fields(client, auth_headers):
    files = {"file": ("f.log", io.BytesIO(b'{"src_ip":"7.7.7.7","dst_ip":"8.8.8.8","action":"deny"}'),
                       "text/plain")}
    client.post("/api/ingest/upload", files=files, headers=auth_headers)

    by_ip = client.get("/api/events", params={"source_ip": "7.7.7.7"}, headers=auth_headers).json()
    assert by_ip["total"] >= 1

    by_action = client.get("/api/events", params={"action": "deny"}, headers=auth_headers).json()
    assert by_action["total"] >= 1


def test_ac14_json_and_jsonl_export_valid(client, auth_headers):
    files = {"file": ("e.log", io.BytesIO(b'{"src_ip":"3.3.3.3","action":"allow"}'), "text/plain")}
    client.post("/api/ingest/upload", files=files, headers=auth_headers)

    json_resp = client.get("/api/export/json", headers=auth_headers)
    assert json_resp.status_code == 200
    payload = json.loads(json_resp.content)
    assert payload["exported_count"] >= 1
    assert payload["events"][0]["raw_event"]["raw_message"]

    jsonl_resp = client.get("/api/export/jsonl", headers=auth_headers)
    assert jsonl_resp.status_code == 200
    lines = [l for l in jsonl_resp.text.splitlines() if l.strip()]
    assert len(lines) >= 1
    parsed_line = json.loads(lines[0])
    assert "event_id" in parsed_line


def test_ac15_parser_onboarding_save_and_reuse_mapping(client, auth_headers):
    files = {"file": ("unk.log", io.BytesIO(b"totally custom vendor format xyz=123"), "text/plain")}
    client.post("/api/ingest/upload", files=files, headers=auth_headers)

    samples = client.get("/api/training/unknown-samples", headers=auth_headers).json()
    assert len(samples) >= 1
    raw_id = samples[0]["raw_event_id"]

    suggestion = client.post(f"/api/training/suggest/{raw_id}", headers=auth_headers)
    assert suggestion.status_code == 200
    record_id = suggestion.json()["training_record_id"]

    approve = client.post(f"/api/training/records/{record_id}/approve",
                           json={"final_mapping": {"xyz": "vendor_fields.xyz"}}, headers=auth_headers)
    assert approve.status_code == 200

    mappings = client.get("/api/parsers/mappings", headers=auth_headers).json()
    assert any(m["status"] == "approved" for m in mappings)


def test_parser_list_reflects_builtin_parsers(client, auth_headers):
    resp = client.get("/api/parsers", headers=auth_headers)
    names = [p["name"] for p in resp.json()]
    for expected in ("json_parser", "csv_parser", "xml_parser", "cef_parser",
                      "leef_parser", "syslog_parser", "kv_parser", "generic_fallback_parser"):
        assert expected in names


def test_alert_rule_create_and_evaluate(client, auth_headers):
    files = {"file": ("crit.log", io.BytesIO(b'{"src_ip":"4.4.4.4","action":"deny","severity":"critical"}'),
                       "text/plain")}
    client.post("/api/ingest/upload", files=files, headers=auth_headers)

    create = client.post("/api/alerts", json={
        "rule_name": "critical-severity", "field": "severity", "operator": "eq", "value": "critical",
    }, headers=auth_headers)
    assert create.status_code == 200

    evaluate = client.post("/api/alerts/evaluate", headers=auth_headers)
    assert evaluate.status_code == 200
    assert evaluate.json()["matches"] >= 1


def test_health_endpoint_no_auth_required(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
