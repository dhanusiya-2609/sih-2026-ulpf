import xml.etree.ElementTree as ET
from .base import BaseParser, ParseResult
from .json_parser import apply_common_aliases


class XMLParser(BaseParser):
    name = "xml_parser"
    version = "1.0"
    format_family = "xml"

    def detect(self, raw_text: str) -> float:
        t = raw_text.strip()
        if t.startswith("<") and not t.startswith("<1") and ">" in t:
            try:
                ET.fromstring(t)
                return 0.9
            except Exception:
                return 0.0
        return 0.0

    def parse(self, raw_text: str) -> ParseResult:
        warnings: list[str] = []
        try:
            root = ET.fromstring(raw_text.strip())
        except Exception as e:
            return ParseResult(status="failed", parser_name=self.name,
                                parser_version=self.version, warnings=[f"invalid XML: {e}"])

        flat: dict = {}
        _walk(root, flat)
        vendor_fields: dict = {}
        fields = apply_common_aliases(flat, vendor_fields, warnings)
        ts_raw = fields.pop("event_timestamp_raw", None)
        status = "success" if fields else "partial"
        if not fields:
            warnings.append("no recognizable fields found; all elements preserved as vendor_fields")

        return ParseResult(status=status, parser_name=self.name, parser_version=self.version,
                            fields=fields, vendor_fields=vendor_fields, warnings=warnings,
                            event_timestamp_raw=ts_raw)


def _walk(elem: ET.Element, out: dict, prefix: str = ""):
    tag = elem.tag.split("}")[-1]  # strip namespace
    key = f"{prefix}.{tag}" if prefix else tag
    for name, val in elem.attrib.items():
        out[f"{key}.@{name}"] = val
    children = list(elem)
    if children:
        for child in children:
            _walk(child, out, key)
    else:
        text = (elem.text or "").strip()
        if text:
            out[key] = text
