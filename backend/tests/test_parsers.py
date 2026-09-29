from app.parsers.registry import registry
from app.parsers.json_parser import JSONParser
from app.parsers.csv_parser import CSVParser
from app.parsers.xml_parser import XMLParser
from app.parsers.cef_parser import CEFParser
from app.parsers.leef_parser import LEEFParser
from app.parsers.syslog_parser import SyslogParser
from app.parsers.kv_parser import KVParser
from app.parsers.generic_parser import GenericFallbackParser


def test_json_parser_extracts_common_fields():
    p = JSONParser()
    result = p.parse('{"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "action": "allow"}')
    assert result.status == "success"
    assert result.fields["source_ip"] == "10.0.0.1"
    assert result.fields["destination_ip"] == "10.0.0.2"
    assert result.fields["action"] == "allow"


def test_json_parser_invalid_json_fails_gracefully():
    p = JSONParser()
    result = p.parse("{not valid json")
    assert result.status == "failed"
    assert result.warnings


def test_csv_parser_with_header():
    p = CSVParser()
    text = "src_ip,dst_ip,action\n192.168.1.1,8.8.8.8,allow"
    result = p.parse(text)
    assert result.status == "success"
    assert result.fields["source_ip"] == "192.168.1.1"


def test_csv_parser_no_header_positional():
    p = CSVParser()
    result = p.parse("192.168.1.1,8.8.8.8,allow")
    assert "no header row" in " ".join(result.warnings)
    assert "column_1" in result.vendor_fields


def test_xml_parser_basic():
    p = XMLParser()
    xml_text = "<event><src_ip>10.1.1.1</src_ip><dst_ip>10.1.1.2</dst_ip><action>deny</action></event>"
    result = p.parse(xml_text)
    assert result.status == "success"
    assert result.fields["source_ip"] == "10.1.1.1"
    assert result.fields["action"] == "deny"


def test_xml_parser_malformed_does_not_crash():
    p = XMLParser()
    result = p.parse("<event><unterminated>")
    assert result.status == "failed"


def test_cef_parser():
    p = CEFParser()
    cef = "CEF:0|Palo Alto Networks|PAN-OS|10.1|traffic|Traffic Log|3|src=192.168.1.1 dst=8.8.8.8 act=allow"
    result = p.parse(cef)
    assert result.status == "success"
    assert result.fields["source_ip"] == "192.168.1.1"
    assert result.fields["action"] == "allow"
    assert result.vendor_fields["device_product"] == "PAN-OS"


def test_leef_parser():
    p = LEEFParser()
    leef = "LEEF:2.0|Fortinet|FortiGate|6.0|1000|src=10.0.0.1\tdst=10.0.0.2\taction=deny"
    result = p.parse(leef)
    assert result.status == "success"
    assert result.fields["source_ip"] == "10.0.0.1"


def test_syslog_parser_cisco_deny():
    p = SyslogParser()
    text = "<189>Oct 11 22:14:15 router1 %SEC-6-IPACCESSLOGP: list 101 denied tcp 192.168.1.10(50000) -> 10.0.0.5(443), 1 packet"
    result = p.parse(text)
    assert result.status == "success"
    assert result.fields["action"] == "deny"
    assert result.fields["source_ip"] == "192.168.1.10"
    assert result.fields["destination_port"] == "443"


def test_syslog_parser_linux_auth_failure():
    p = SyslogParser()
    text = "<38>Oct 11 22:20:00 linuxsrv1 sshd[1234]: Failed password for invalid user admin from 10.0.0.99 port 51222 ssh2"
    result = p.parse(text)
    assert result.fields["event_category"] == "authentication"
    assert result.fields["outcome"] == "failure"
    assert result.fields["source_ip"] == "10.0.0.99"


def test_syslog_parser_rejects_non_syslog():
    p = SyslogParser()
    result = p.parse("this is not a syslog line at all")
    assert result.status == "failed"


def test_kv_parser_fortinet_style():
    p = KVParser()
    text = "date=2024-10-11 time=22:16:00 devname=FGT01 action=deny srcip=192.168.1.15 dstip=10.0.0.9"
    result = p.parse(text)
    assert result.status == "success"
    assert result.fields["source_ip"] == "192.168.1.15"


def test_generic_fallback_never_fails():
    p = GenericFallbackParser()
    result = p.parse("some totally unstructured garbage !!! %%% \x00\x01")
    assert result.status == "unrecognized"
    assert result.fields["message"]


def test_registry_auto_detects_json():
    result = registry.parse('{"src_ip": "1.2.3.4", "action": "deny"}')
    assert result.parser_name == "json_parser"


def test_registry_auto_detects_cef():
    result = registry.parse("CEF:0|Vendor|Product|1.0|100|Test|5|src=1.1.1.1 dst=2.2.2.2")
    assert result.parser_name == "cef_parser"


def test_registry_never_raises_on_garbage():
    # AC-10: malformed/unknown input must never crash the pipeline
    garbage_inputs = ["", "\x00\x01\x02", "{{{{", "<<<>>>", "=====", "a" * 5000]
    for g in garbage_inputs:
        result = registry.parse(g)
        assert result.status in ("success", "partial", "failed", "unrecognized")


def test_registry_falls_back_to_generic_on_parser_failure():
    # A string that looks like it starts JSON but isn't valid should still
    # produce a usable (fallback) result rather than an unhandled exception.
    result = registry.parse("{this is not valid json but looks like it}")
    assert result.status in ("unrecognized", "partial", "failed")
