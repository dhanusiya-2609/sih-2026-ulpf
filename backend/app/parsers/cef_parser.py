import re
from .base import BaseParser, ParseResult
from .json_parser import apply_common_aliases

# CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
CEF_HEADER_RE = re.compile(r"CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$")


# Optional syslog envelope before the CEF marker: "<PRI>Mon DD HH:MM:SS host "
_ENVELOPE_RE = re.compile(
    r"^<\d{1,3}>\s*(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+(?P<host>\S+)\s*$"
)


def _split_cef_extension(ext: str) -> dict:
    """CEF extension is space-separated key=value pairs; values may contain
    escaped '=' or spaces, so split conservatively on ' key=' boundaries."""
    out = {}
    # Insert a marker before each " token=" occurrence, then split on marker.
    parts = re.split(r"\s+(?=[A-Za-z0-9_]+=)", ext.strip())
    for part in parts:
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


class CEFParser(BaseParser):
    name = "cef_parser"
    version = "1.0"
    format_family = "cef"

    def detect(self, raw_text: str) -> float:
        if "CEF:" in raw_text:
            return 0.9
        return 0.0

    def parse(self, raw_text: str) -> ParseResult:
        idx = raw_text.find("CEF:")
        prefix = raw_text[:idx]  # e.g. syslog envelope before the CEF marker
        cef_part = raw_text[idx:]
        m = CEF_HEADER_RE.match(cef_part)
        if not m:
            return ParseResult(status="failed", parser_name=self.name, parser_version=self.version,
                                warnings=["CEF marker found but header did not match expected format"])

        version, vendor, product, dev_version, sig_id, name, severity, ext = m.groups()
        ext_fields = _split_cef_extension(ext)

        vendor_fields: dict = {
            "cef_version": version, "device_vendor": vendor, "device_product": product,
            "device_version": dev_version, "signature_id": sig_id,
        }
        warnings: list[str] = []
        fields = apply_common_aliases(ext_fields, vendor_fields, warnings)
        fields.setdefault("severity", severity)
        fields.setdefault("message", name)
        ts_raw = fields.pop("event_timestamp_raw", None)

        # The device *name* is the reporting host from the syslog envelope,
        # not the vendor (which is kept in vendor_fields["device_vendor"]).
        env = _ENVELOPE_RE.match(prefix.strip()) if prefix.strip() else None
        if env:
            fields.setdefault("device_name", env.group("host"))
            ts_raw = ts_raw or env.group("ts")

        return ParseResult(status="success", parser_name=self.name, parser_version=self.version,
                            fields=fields, vendor_fields=vendor_fields, warnings=warnings,
                            event_timestamp_raw=ts_raw)
