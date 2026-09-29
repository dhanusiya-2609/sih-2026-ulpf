import re
from .base import BaseParser, ParseResult
from .json_parser import apply_common_aliases

KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def extract_kv(text: str) -> dict:
    out = {}
    for k, v in KV_RE.findall(text):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        out[k] = v
    return out


class KVParser(BaseParser):
    """Generic key=value log parser, e.g. FortiGate-style syslog bodies:
    date=2024-10-11 time=22:16:00 devname=FGT01 action=deny srcip=... dstip=...
    """
    name = "kv_parser"
    version = "1.0"
    format_family = "kv"

    def detect(self, raw_text: str) -> float:
        matches = KV_RE.findall(raw_text)
        if len(matches) >= 3:
            # ratio of matched kv text length to total, to avoid false positives
            # on free-text messages that happen to contain one "x=y"
            return min(0.85, 0.3 + 0.1 * len(matches))
        return 0.0

    def parse(self, raw_text: str) -> ParseResult:
        kv = extract_kv(raw_text)
        if not kv:
            return ParseResult(status="failed", parser_name=self.name, parser_version=self.version,
                                warnings=["no key=value pairs found"])
        vendor_fields: dict = {}
        warnings: list[str] = []
        fields = apply_common_aliases(kv, vendor_fields, warnings)
        ts_raw = fields.pop("event_timestamp_raw", None)
        if not ts_raw and "date" in kv and "time" in kv:
            ts_raw = f"{kv['date']} {kv['time']}"

        status = "success" if fields else "partial"
        return ParseResult(status=status, parser_name=self.name, parser_version=self.version,
                            fields=fields, vendor_fields=vendor_fields, warnings=warnings,
                            event_timestamp_raw=ts_raw)
