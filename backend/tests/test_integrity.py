import io

from app.normalization import compute_content_hash


def test_content_hash_deterministic():
    a = compute_content_hash("hello world")
    b = compute_content_hash("hello world")
    assert a == b
    assert len(a) == 64  # sha256 hex digest


def test_content_hash_changes_with_content():
    a = compute_content_hash("event A")
    b = compute_content_hash("event B")
    assert a != b


def test_raw_message_preserved_verbatim_after_upload(client, auth_headers):
    raw_line = "<189>Oct 11 22:14:15 router1 %SEC-6-IPACCESSLOGP: list 101 denied tcp 192.168.1.10(50000) -> 10.0.0.5(443), 1 packet"
    files = {"file": ("sample.log", io.BytesIO(raw_line.encode()), "text/plain")}
    resp = client.post("/api/ingest/upload", files=files, headers=auth_headers)
    assert resp.status_code == 200, resp.text
    job = resp.json()
    assert job["total_events"] == 1
    assert job["success_count"] == 1

    search = client.get("/api/events", params={"page_size": 5}, headers=auth_headers)
    event_id = search.json()["items"][0]["event_id"]

    raw_resp = client.get(f"/api/events/{event_id}/raw", headers=auth_headers)
    assert raw_resp.status_code == 200
    body = raw_resp.json()
    assert body["raw_message"] == raw_line  # byte-for-byte preserved
    assert body["integrity_verified"] is True


def test_normalized_event_traces_to_raw_event(client, auth_headers):
    files = {"file": ("t.log", io.BytesIO(b'{"src_ip":"1.1.1.1","action":"allow"}'), "text/plain")}
    resp = client.post("/api/ingest/upload", files=files, headers=auth_headers)
    assert resp.status_code == 200

    search = client.get("/api/events", params={"page_size": 5}, headers=auth_headers)
    event_id = search.json()["items"][0]["event_id"]

    detail = client.get(f"/api/events/{event_id}", headers=auth_headers).json()
    assert detail["raw_event"]["raw_event_id"]
    assert detail["raw_event"]["content_hash"]
    assert detail["integrity"]["hash_match"] is True


def test_duplicate_events_preserved_as_separate_records(client, auth_headers):
    dup_line = '{"src_ip":"9.9.9.9","action":"deny"}'
    for _ in range(2):
        files = {"file": ("dup.log", io.BytesIO(dup_line.encode()), "text/plain")}
        client.post("/api/ingest/upload", files=files, headers=auth_headers)

    search = client.get("/api/events", params={"ip": "9.9.9.9", "page_size": 10}, headers=auth_headers)
    items = search.json()["items"]
    assert len(items) == 2  # both duplicates preserved, not deduplicated away
    assert items[0]["event_id"] != items[1]["event_id"]
