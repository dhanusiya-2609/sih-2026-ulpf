import io
from pathlib import Path

import pytest

from app.vendor_detect import detect_vendor, detect_vendor_for_lines, guess_device_type

SAMPLE_DIR = Path(__file__).resolve().parents[2] / "sample_logs"


def test_detects_cisco_from_mnemonic():
    line = "<189>Oct 11 22:14:15 rtr1 %SEC-6-IPACCESSLOGP: list 101 denied tcp 1.1.1.1(1) -> 2.2.2.2(2)"
    assert detect_vendor(line) == "Cisco"


def test_detects_vendor_from_cef_header_and_canonicalises():
    line = "CEF:0|Palo Alto Networks|PAN-OS|11.1|TRAFFIC|Traffic allow|3|src=1.1.1.1"
    assert detect_vendor(line) == "Palo Alto Networks"


def test_detects_fortinet_from_native_kv():
    line = "<189>date=2025-10-11 time=22:50:00 devname=FGT-01 devid=FG100E logid=0000000013 type=traffic action=deny"
    assert detect_vendor(line) == "Fortinet"


def test_detects_linux_from_daemon_tag():
    line = "<38>Oct 11 23:00:00 app-srv-1 sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
    assert detect_vendor(line) == "Linux"


def test_no_signature_returns_none_not_a_guess():
    assert detect_vendor("completely unstructured free text") is None
    assert detect_vendor('{"src_ip": "1.1.1.1"}') is None


def test_majority_vote_ignores_a_corrupted_line():
    lines = [
        "<189>date=2025-10-11 time=1 devname=A devid=FG100E logid=1 type=traffic",
        "<189>date=2025-10-11 time=2 devname=A devid=FG100E logid=2 type=traffic",
        "corrupted_entry_missing_structure_%%%",
    ]
    assert detect_vendor_for_lines(lines) == "Fortinet"


def test_device_type_hints():
    assert guess_device_type("Palo Alto Networks") == "firewall"
    assert guess_device_type("Linux") == "server"
    assert guess_device_type("Cisco", "cisco_catalyst_switch SPANTREE") == "switch"
    assert guess_device_type("Cisco", "core-rtr-1 OSPF") == "router"
    assert guess_device_type(None) == "unknown"


def test_event_gets_vendor_without_any_source(client, auth_headers):
    """Plain upload with NO source attached: vendor must still be detected."""
    line = b"<189>Oct 11 22:14:15 rtr1 %SEC-6-IPACCESSLOGP: list 101 denied tcp 9.9.9.9(1) -> 8.8.8.8(2)"
    client.post("/api/ingest/upload", files={"file": ("x.log", io.BytesIO(line), "text/plain")},
                headers=auth_headers)
    res = client.get("/api/events", params={"ip": "9.9.9.9"}, headers=auth_headers).json()
    assert res["items"][0]["vendor"] == "Cisco"


@pytest.mark.skipif(not SAMPLE_DIR.exists(), reason="sample_logs directory not present")
@pytest.mark.parametrize("filename,vendor,device_type", [
    ("cisco_ios_router.log", "Cisco", "router"),
    ("cisco_catalyst_switch.log", "Cisco", "switch"),
    ("paloalto_firewall.log", "Palo Alto Networks", "firewall"),
    ("fortinet_fortigate.log", "Fortinet", "firewall"),
    ("linux_server.log", "Linux", "server"),
])
def test_bulk_upload_detects_vendor_for_each_sample_log(client, auth_headers, filename, vendor, device_type):
    data = (SAMPLE_DIR / filename).read_bytes()
    resp = client.post("/api/sources/upload", files=[("files", (filename, io.BytesIO(data), "text/plain"))],
                       headers=auth_headers)
    assert resp.status_code == 200, resp.text
    result = resp.json()["results"][0]
    assert result["vendor"] == vendor
    assert result["device_type"] == device_type

    # ...and the ingested EVENTS carry that vendor too (what the dashboard groups by)
    events = client.get("/api/events", params={"vendor": vendor, "page_size": 100}, headers=auth_headers).json()
    assert events["total"] >= 1
