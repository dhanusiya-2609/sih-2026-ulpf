import re
from .base import BaseParser, ParseResult
from .json_parser import apply_common_aliases

_ENVELOPE_RE = re.compile(
    r"^<\d{1,3}>\s*(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s*$"
)

# LEEF:Version|Vendor|Product|Version|EventID|[Delimiter|]Extension
LEEF_HEADER_RE = re.compile(r"LEEF:([\d.]+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$")


class LEEFParser(BaseParser):
    name = "leef_parser"
    version = "1.0"
    format_family = "leef"

    def detect(self, raw_text: str) -> float:
        if "LEEF:" in raw_text:
            return 0.9
        return 0.0

    def parse(self, raw_text: str) -> ParseResult:
        idx = raw_text.find("LEEF:")
        leef_part = raw_text[idx:]
        m = LEEF_HEADER_RE.match(leef_part)
        if not m:
            return ParseResult(status="failed", parser_name=self.name, parser_version=self.version,
                                warnings=["LEEF marker found but header did not match expected format"])

        version, vendor, product, dev_version, event_id, rest = m.groups()
        delimiter = "\t"
        ext = rest
        # LEEF 2.0 allows an explicit delimiter field before the extension
        if version.startswith("2") and "|" in rest and len(rest.split("|", 1)[0]) <= 3:
            delim_field, ext = rest.split("|", 1)
            delimiter = {"tab": "\t"}.get(delim_field.lower(), delim_field or "\t")

        ext_fields = {}
        for part in ext.split(delimiter) if delimiter else ext.split():
            if "=" in part:
                k, v = part.split("=", 1)
                ext_fields[k.strip()] = v.strip()

        vendor_fields: dict = {"leef_version": version, "device_vendor": vendor, "device_product": product,
                                "device_version": dev_version, "event_id": event_id}
        warnings: list[str] = []
        fields = apply_common_aliases(ext_fields, vendor_fields, warnings)
        ts_raw = fields.pop("event_timestamp_raw", None)
        prefix = raw_text[:idx].strip()
        env = _ENVELOPE_RE.match(prefix) if prefix else None
        if env:
            fields.setdefault("device_name", env.group("host"))
            ts_raw = ts_raw or env.group("ts")

        status = "success" if ext_fields else "partial"
        return ParseResult(status=status, parser_name=self.name, parser_version=self.version,
                            fields=fields, vendor_fields=vendor_fields, warnings=warnings,
                            event_timestamp_raw=ts_raw)
