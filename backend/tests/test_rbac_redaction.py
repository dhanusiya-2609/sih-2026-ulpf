import io

import pytest


def _create_user(client, admin_headers, username, role):
    resp = client.post("/api/auth/users", json={"username": username, "password": "pass1234", "role": role},
                        headers=admin_headers)
    assert resp.status_code == 200, resp.text
    login = client.post("/api/auth/login", json={"username": username, "password": "pass1234"})
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_viewer_cannot_create_source(client, auth_headers):
    viewer_headers = _create_user(client, auth_headers, "viewer1", "viewer")
    resp = client.post("/api/sources", json={
        "source_id": "rbac-src-1", "device_name": "D", "vendor": "V", "device_type": "router",
    }, headers=viewer_headers)
    assert resp.status_code == 403


def test_analyst_can_create_but_not_delete_source(client, auth_headers):
    analyst_headers = _create_user(client, auth_headers, "analyst1", "analyst")
    create = client.post("/api/sources", json={
        "source_id": "rbac-src-2", "device_name": "D", "vendor": "V", "device_type": "router",
    }, headers=analyst_headers)
    assert create.status_code == 200

    delete = client.delete("/api/sources/rbac-src-2", headers=analyst_headers)
    assert delete.status_code == 403


def test_admin_can_delete_source(client, auth_headers):
    client.post("/api/sources", json={
        "source_id": "rbac-src-3", "device_name": "D", "vendor": "V", "device_type": "router",
    }, headers=auth_headers)
    resp = client.delete("/api/sources/rbac-src-3", headers=auth_headers)
    assert resp.status_code == 200


def test_viewer_cannot_see_raw_message_but_analyst_can(client, auth_headers):
    viewer_headers = _create_user(client, auth_headers, "viewer2", "viewer")
    analyst_headers = _create_user(client, auth_headers, "analyst2", "analyst")

    files = {"file": ("v.log", io.BytesIO(b'{"src_ip":"1.1.1.1","action":"allow"}'), "text/plain")}
    client.post("/api/ingest/upload", files=files, headers=auth_headers)

    search = client.get("/api/events", params={"page_size": 5}, headers=auth_headers).json()
    event_id = search["items"][0]["event_id"]

    viewer_raw = client.get(f"/api/events/{event_id}/raw", headers=viewer_headers)
    assert viewer_raw.status_code == 403

    analyst_raw = client.get(f"/api/events/{event_id}/raw", headers=analyst_headers)
    assert analyst_raw.status_code == 200
    assert analyst_raw.json()["raw_message"]

    viewer_detail = client.get(f"/api/events/{event_id}", headers=viewer_headers).json()
    assert viewer_detail["raw_event"]["raw_message"] is None

    analyst_detail = client.get(f"/api/events/{event_id}", headers=analyst_headers).json()
    assert analyst_detail["raw_event"]["raw_message"] is not None


def test_redaction_masks_sensitive_vendor_field(client, auth_headers):
    line = '{"src_ip":"2.2.2.2","action":"login-failed","password":"hunter2","user":"admin"}'
    files = {"file": ("sec.log", io.BytesIO(line.encode()), "text/plain")}
    client.post("/api/ingest/upload", files=files, headers=auth_headers)

    search = client.get("/api/events", params={"ip": "2.2.2.2", "page_size": 5}, headers=auth_headers).json()
    event_id = search["items"][0]["event_id"]

    detail = client.get(f"/api/events/{event_id}", headers=auth_headers).json()
    assert detail["vendor_fields"].get("password") == "***REDACTED***"


def test_redaction_masks_password_in_message_text(client, auth_headers):
    line = "some system event password=hunter2 occurred"
    files = {"file": ("sec2.log", io.BytesIO(line.encode()), "text/plain")}
    client.post("/api/ingest/upload", files=files, headers=auth_headers)

    search = client.get("/api/events", params={"q": "system event", "page_size": 5}, headers=auth_headers).json()
    assert "hunter2" not in search["items"][0]["message"]
    assert "***REDACTED***" in search["items"][0]["message"]


def test_bulk_source_upload_creates_sources_and_ingests(client, auth_headers):
    files = [
        ("files", ("router-a.log", io.BytesIO(b'{"src_ip":"1.1.1.1","action":"allow"}'), "text/plain")),
        ("files", ("router-a.log", io.BytesIO(b'{"src_ip":"2.2.2.2","action":"deny"}'), "text/plain")),
    ]
    resp = client.post("/api/sources/upload", files=files, headers=auth_headers)
    assert resp.status_code == 200, resp.text
    results = resp.json()["results"]
    assert len(results) == 2
    assert results[0]["source_id"] == "router-a"
    assert results[1]["source_id"] == "router-a-2"  # duplicate filename gets a unique slug
    assert results[0]["total_events"] == 1
    assert results[0]["success_count"] == 1

    sources = client.get("/api/sources", headers=auth_headers).json()
    ids = {s["source_id"] for s in sources}
    assert "router-a" in ids and "router-a-2" in ids


def test_bulk_source_upload_requires_analyst_role(client, auth_headers):
    viewer_headers = _create_user(client, auth_headers, "viewer3", "viewer")
    files = [("files", ("x.log", io.BytesIO(b'{"a":"b"}'), "text/plain"))]
    resp = client.post("/api/sources/upload", files=files, headers=viewer_headers)
    assert resp.status_code == 403
