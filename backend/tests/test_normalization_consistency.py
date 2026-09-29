from app.parsers.registry import registry
from app.normalization import normalize


SAME_CONNECTION_IN_DIFFERENT_FORMATS = [
    # (label, raw_text)
    ("json", '{"src_ip": "10.5.5.1", "dst_ip": "10.5.5.2", "action": "deny", "src_port": "5001", "dst_port": "443"}'),
    ("fortinet_kv", "date=2025-01-01 time=00:00:00 srcip=10.5.5.1 dstip=10.5.5.2 srcport=5001 dstport=443 action=deny"),
    ("cef", "CEF:0|Vendor|Product|1.0|100|Test|5|src=10.5.5.1 dst=10.5.5.2 spt=5001 dpt=443 act=deny"),
    ("csv", "src_ip,dst_ip,action,src_port,dst_port\n10.5.5.1,10.5.5.2,deny,5001,443"),
]


def test_cross_vendor_field_mapping_consistency():
    """
    AC-06/07: regardless of vendor-specific field naming (src/srcip/src_ip,
    dst/dstip/dst_ip, spt/srcport, dpt/dstport, act/action), the same
    logical connection must normalize to identical common-schema field
    names and values. This is the core promise of the normalization layer.
    """
    normalized_results = []
    for label, raw in SAME_CONNECTION_IN_DIFFERENT_FORMATS:
        parse_result = registry.parse(raw)
        norm = normalize(parse_result)
        normalized_results.append((label, norm))

    for label, norm in normalized_results:
        assert norm["source_ip"] == "10.5.5.1", f"{label}: source_ip mismatch -> {norm}"
        assert norm["destination_ip"] == "10.5.5.2", f"{label}: destination_ip mismatch -> {norm}"
        assert norm["event_action"] == "deny", f"{label}: action mismatch -> {norm}"
        assert norm["source_port"] == 5001, f"{label}: source_port mismatch -> {norm}"
        assert norm["destination_port"] == 443, f"{label}: destination_port mismatch -> {norm}"


def test_severity_scales_normalize_to_common_words():
    """Cisco syslog PRI-derived severity and CEF's 0-10 numeric severity
    scale are different source conventions but both normalize to the same
    small vocabulary of severity words."""
    cisco = registry.parse(
        "<180>Oct 11 22:18:10 rtr1 %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 10.0.0.1]"
    )
    cisco_norm = normalize(cisco)
    assert cisco_norm["event_severity"] in ("warning", "error")

    cef_high = registry.parse("CEF:0|V|P|1.0|100|Test|9|src=1.1.1.1 dst=2.2.2.2")
    cef_norm = normalize(cef_high)
    assert cef_norm["event_severity"] == "critical"

    cef_low = registry.parse("CEF:0|V|P|1.0|100|Test|1|src=1.1.1.1 dst=2.2.2.2")
    cef_low_norm = normalize(cef_low)
    assert cef_low_norm["event_severity"] == "low"
