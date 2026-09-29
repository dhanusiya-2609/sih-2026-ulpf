import re
from .base import BaseParser, ParseResult
from .kv_parser import KVParser, extract_kv
from .json_parser import apply_common_aliases

# <PRI>Mon DD HH:MM:SS host tag: message   (RFC3164-ish, very widely used by
# network gear even when not strictly compliant)
SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>\s*"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<body>.*)$",
    re.DOTALL,
)

# Cisco IOS/Catalyst style: %FACILITY-SEVERITY-MNEMONIC: message
CISCO_MNEMONIC_RE = re.compile(r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<msg>.*)$")

# "192.168.1.10(50000) -> 10.0.0.5(443)" style connection tuples seen in ACL/deny logs
CONN_TUPLE_RE = re.compile(
    r"(?P<proto>tcp|udp|icmp)\s+(?P<sip>\d{1,3}(?:\.\d{1,3}){3})(?:\((?P<sport>\d+)\))?"
    r"\s*(?:->|to)\s*(?P<dip>\d{1,3}(?:\.\d{1,3}){3})(?:\((?P<dport>\d+)\))?",
    re.IGNORECASE,
)

# Common Linux auth message: "Failed password for [invalid user ]NAME from IP port PORT ssh2"
LINUX_AUTH_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)",
    re.IGNORECASE,
)

CISCO_SEVERITY_MAP = {
    "0": "emergency", "1": "alert", "2": "critical", "3": "error",
    "4": "warning", "5": "notice", "6": "informational", "7": "debug",
}

PRI_SEVERITY_MAP = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "informational", 7: "debug",
}


class SyslogParser(BaseParser):
    name = "syslog_parser"
    version = "1.0"
    format_family = "syslog"

    def detect(self, raw_text: str) -> float:
        if raw_text.lstrip().startswith("<") and SYSLOG_RE.match(raw_text.strip()):
            return 0.9
        return 0.0

    def parse(self, raw_text: str) -> ParseResult:
        warnings: list[str] = []
        m = SYSLOG_RE.match(raw_text.strip())
        if not m:
            return ParseResult(status="failed", parser_name=self.name, parser_version=self.version,
                                warnings=["input does not match syslog PRI/timestamp/host envelope"])

        pri = int(m.group("pri"))
        facility = pri // 8
        severity_num = pri % 8
        ts_raw = m.group("ts")
        host = m.group("host")
        body = m.group("body")

        fields: dict = {
            "device_name": host,
            "severity": PRI_SEVERITY_MAP.get(severity_num, str(severity_num)),
        }
        vendor_fields: dict = {"syslog_facility_code": facility, "syslog_pri": pri}

        # tag: message  (e.g. "sshd[1234]: message" or "%SEC-6-...: message")
        tag = None
        msg = body
        if ":" in body:
            possible_tag, rest = body.split(":", 1)
            if len(possible_tag) < 40:
                tag = possible_tag.strip()
                msg = rest.strip()
        if tag:
            vendor_fields["syslog_tag"] = tag

        cm = CISCO_MNEMONIC_RE.search(body)
        if cm:
            vendor_fields["cisco_facility"] = cm.group("facility")
            vendor_fields["cisco_mnemonic"] = cm.group("mnemonic")
            fields["severity"] = CISCO_SEVERITY_MAP.get(cm.group("severity"), fields["severity"])
            msg = cm.group("msg").strip()
            mnemonic_lower = cm.group("mnemonic").lower()
            facility_lower = cm.group("facility").lower()
            if "denied" in msg.lower() or "permitted" in msg.lower():
                fields["action"] = "deny" if "denied" in msg.lower() else "allow"
                fields.setdefault("event_category", "network")
                fields["event_type"] = "connection"
            if "updown" in mnemonic_lower or facility_lower == "link" or facility_lower == "lineproto":
                fields["event_type"] = "interface_status"
                fields.setdefault("event_category", "network")
            if "login_failed" in mnemonic_lower or "login_failed" in facility_lower:
                fields["event_category"] = "authentication"
                fields["event_type"] = "login"
                fields["outcome"] = "failure"
                fields["action"] = "deny"
                src_m = re.search(r"\[Source:\s*([\d.]+)\]", msg)
                if src_m:
                    fields["source_ip"] = src_m.group(1)
                user_m = re.search(r"\[user:\s*([^\]]+)\]", msg)
                if user_m:
                    vendor_fields["auth_user"] = user_m.group(1)
            if mnemonic_lower == "config_i":
                fields["event_type"] = "configuration_change"
                fields.setdefault("event_category", "administrative")
            if "adjchg" in mnemonic_lower:
                fields["event_type"] = "routing_adjacency_change"
                fields.setdefault("event_category", "network")

        ct = CONN_TUPLE_RE.search(msg)
        if ct:
            fields.setdefault("protocol", ct.group("proto"))
            fields.setdefault("source_ip", ct.group("sip"))
            fields.setdefault("destination_ip", ct.group("dip"))
            if ct.group("sport"):
                fields.setdefault("source_port", ct.group("sport"))
            if ct.group("dport"):
                fields.setdefault("destination_port", ct.group("dport"))

        la = LINUX_AUTH_RE.search(msg)
        if la:
            fields.setdefault("source_ip", la.group("ip"))
            fields.setdefault("source_port", la.group("port"))
            fields["action"] = "deny"
            fields["event_category"] = "authentication"
            fields["event_type"] = "login"
            fields["outcome"] = "failure"
            vendor_fields["auth_user"] = la.group("user")

        # If the body itself is key=value structured (Fortinet-over-syslog),
        # delegate to the KV parser and merge -- explicit fields already set
        # above take precedence (they came from higher-confidence patterns).
        kv = extract_kv(msg)
        if len(kv) >= 3:
            kv_vendor: dict = {}
            kv_fields = apply_common_aliases(kv, kv_vendor, warnings)
            for k, v in kv_fields.items():
                fields.setdefault(k, v)
            vendor_fields.update(kv_vendor)
            msg_from_kv = kv.get("msg") or kv.get("message")
            if msg_from_kv:
                msg = msg_from_kv

        fields["message"] = msg

        status = "success" if len(fields) > 2 else "partial"
        if status == "partial":
            warnings.append("syslog envelope parsed but message body yielded few structured fields")

        return ParseResult(status=status, parser_name=self.name, parser_version=self.version,
                            fields=fields, vendor_fields=vendor_fields, warnings=warnings,
                            event_timestamp_raw=ts_raw)
