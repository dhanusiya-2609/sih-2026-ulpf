import json
from .base import BaseParser, ParseResult

# Common alias sets used across all parsers to map heterogeneous vendor field
# names into the shared intermediate representation consumed by normalization.py
SRC_IP_KEYS = {"src", "src_ip", "source_ip", "srcip", "sourceip", "saddr", "sip"}
DST_IP_KEYS = {"dst", "dst_ip", "destination_ip", "dstip", "destinationip", "daddr", "dip"}
SRC_PORT_KEYS = {"src_port", "source_port", "srcport", "sport", "spt"}
DST_PORT_KEYS = {"dst_port", "destination_port", "dstport", "dport", "dpt"}
ACTION_KEYS = {"action", "verdict", "disposition", "act"}
HOST_KEYS = {"device", "hostname", "host", "devname", "dvchost"}
PROTO_KEYS = {"proto", "protocol", "transport_protocol"}
SEVERITY_KEYS = {"severity", "level", "sev", "priority_level"}
MESSAGE_KEYS = {"message", "msg", "description", "desc"}
TIMESTAMP_KEYS = {"timestamp", "time", "date", "eventtime", "@timestamp", "datetime"}


def apply_common_aliases(flat: dict, vendor_fields: dict, warnings: list) -> dict:
    """Map a flat dict of arbitrary source keys onto the shared intermediate
    field names, moving anything unrecognized into vendor_fields untouched."""
    out = {}
    for k, v in flat.items():
        # match on the last path segment so nested keys like "network.src_ip"
        # still resolve to the correct alias
        lk = str(k).lower().strip().split(".")[-1]
        if lk in SRC_IP_KEYS:
            out["source_ip"] = v
        elif lk in DST_IP_KEYS:
            out["destination_ip"] = v
        elif lk in SRC_PORT_KEYS:
            out["source_port"] = v
        elif lk in DST_PORT_KEYS:
            out["destination_port"] = v
        elif lk in ACTION_KEYS:
            out["action"] = v
        elif lk in HOST_KEYS:
            out["device_name"] = v
        elif lk in PROTO_KEYS:
            out["protocol"] = v
        elif lk in SEVERITY_KEYS:
            out["severity"] = v
        elif lk in MESSAGE_KEYS:
            out["message"] = v
        elif lk in TIMESTAMP_KEYS:
            out["event_timestamp_raw"] = str(v)
        else:
            vendor_fields[k] = v
    return out


class JSONParser(BaseParser):
    name = "json_parser"
    version = "1.0"
    format_family = "json"

    def detect(self, raw_text: str) -> float:
        t = raw_text.strip()
        if not t:
            return 0.0
        if t[0] in "{[":
            try:
                json.loads(t)
                return 0.95
            except Exception:
                return 0.0
        return 0.0

    def parse(self, raw_text: str) -> ParseResult:
        warnings: list[str] = []
        try:
            data = json.loads(raw_text)
        except Exception as e:
            return ParseResult(
                status="failed", parser_name=self.name, parser_version=self.version,
                warnings=[f"invalid JSON: {e}"],
            )

        if isinstance(data, list):
            # Multiple events in one payload is out of scope for single-event
            # parse(); the ingestion layer splits JSONL/arrays before calling
            # parsers. If we still get a list, parse the first and warn.
            if not data:
                return ParseResult(status="failed", parser_name=self.name,
                                    parser_version=self.version, warnings=["empty JSON array"])
            data = data[0]
            warnings.append("input was a JSON array; only first element parsed here")

        if not isinstance(data, dict):
            return ParseResult(status="failed", parser_name=self.name, parser_version=self.version,
                                warnings=["top-level JSON value is not an object"])

        flat = _flatten(data)
        vendor_fields: dict = {}
        fields = apply_common_aliases(flat, vendor_fields, warnings)
        ts_raw = fields.pop("event_timestamp_raw", None)

        status = "success" if fields else "partial"
        if not fields:
            warnings.append("no recognizable fields found; all data preserved as vendor_fields")

        return ParseResult(
            status=status, parser_name=self.name, parser_version=self.version,
            fields=fields, vendor_fields=vendor_fields, warnings=warnings,
            event_timestamp_raw=ts_raw,
        )


def _flatten(d: dict, parent_key: str = "", sep: str = ".") -> dict:
    items = {}
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
        if isinstance(v, dict):
            items.update(_flatten(v, new_key, sep))
        else:
            items[new_key] = v
    return items
