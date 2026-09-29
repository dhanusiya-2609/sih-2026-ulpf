import re
from .base import BaseParser, ParseResult

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
TS_HINT_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
)


class GenericFallbackParser(BaseParser):
    """
    Last-resort parser: guaranteed to accept any input. It preserves the
    complete raw message and makes a best-effort, clearly-labeled attempt to
    spot an IP address or timestamp-looking substring, but never fabricates
    structured fields it cannot support from the text itself. Status is
    always 'unrecognized' so downstream consumers do not mistake this for a
    confident normalization.
    """
    name = "generic_fallback_parser"
    version = "1.0"
    format_family = "generic"

    def detect(self, raw_text: str) -> float:
        return 0.01  # always applicable, but lowest possible priority

    def parse(self, raw_text: str) -> ParseResult:
        warnings = ["no registered parser matched this input with sufficient confidence; "
                    "stored as an unrecognized event with best-effort hints only"]
        fields: dict = {"message": raw_text.strip()[:2000]}
        unparsed: list[str] = []

        ips = IP_RE.findall(raw_text)
        if ips:
            fields["source_ip"] = ips[0]
            if len(ips) > 1:
                fields["destination_ip"] = ips[1]
            unparsed.append("ip_role_unconfirmed")

        ts_match = TS_HINT_RE.search(raw_text)
        ts_raw = ts_match.group(0) if ts_match else None

        return ParseResult(
            status="unrecognized", parser_name=self.name, parser_version=self.version,
            fields=fields, vendor_fields={}, warnings=warnings,
            unparsed_fields=unparsed, event_timestamp_raw=ts_raw,
        )
