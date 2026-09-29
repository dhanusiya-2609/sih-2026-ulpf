"""
Base parser contract.

Every parser is independently maintainable/replaceable: it implements
`detect()` (a cheap, non-throwing confidence check) and `parse()` (field
extraction). Parsers must never raise on malformed input from `parse()` in
a way that could crash the pipeline -- callers always wrap parse() calls,
but well-behaved parsers should catch their own internal errors and
degrade to a partial result with warnings instead.
"""
from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class ParseResult:
    """
    Normalized-ish output of a parser, prior to schema mapping.
    `fields` uses common intermediate keys (see normalization.py mapping
    tables) plus anything vendor-specific goes into `vendor_fields`.
    """
    status: str  # "success" | "partial" | "failed" | "unrecognized"
    parser_name: str
    parser_version: str
    fields: dict[str, Any] = field(default_factory=dict)
    vendor_fields: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    unparsed_fields: list[str] = field(default_factory=list)
    event_timestamp_raw: Optional[str] = None


class BaseParser:
    name: str = "base"
    version: str = "1.0"
    format_family: str = "generic"

    def detect(self, raw_text: str) -> float:
        """Return a confidence score in [0.0, 1.0] that this parser applies."""
        raise NotImplementedError

    def parse(self, raw_text: str) -> ParseResult:
        raise NotImplementedError
