import csv
import io
from .base import BaseParser, ParseResult
from .json_parser import apply_common_aliases


class CSVParser(BaseParser):
    name = "csv_parser"
    version = "1.0"
    format_family = "csv"

    def detect(self, raw_text: str) -> float:
        t = raw_text.strip()
        if not t or "\n" in t.strip("\n"):
            pass  # single or multi-line both acceptable (one row per event)
        first_line = t.splitlines()[0] if t else ""
        comma_count = first_line.count(",")
        if comma_count >= 2 and not t.startswith("{") and not t.startswith("<"):
            return 0.6
        return 0.0

    def parse(self, raw_text: str) -> ParseResult:
        warnings: list[str] = []
        lines = [l for l in raw_text.splitlines() if l.strip()]
        if not lines:
            return ParseResult(status="failed", parser_name=self.name,
                                parser_version=self.version, warnings=["empty CSV input"])
        try:
            if len(lines) >= 2:
                reader = csv.DictReader(io.StringIO(raw_text))
                row = next(reader, None)
                if row is None:
                    raise ValueError("no data row")
                flat = dict(row)
            else:
                # Single line, no header available: index-based generic columns
                reader = csv.reader(io.StringIO(raw_text))
                row = next(reader)
                flat = {f"column_{i+1}": v for i, v in enumerate(row)}
                warnings.append("no header row present; columns are positional (column_N)")
        except Exception as e:
            return ParseResult(status="failed", parser_name=self.name,
                                parser_version=self.version, warnings=[f"CSV parse error: {e}"])

        vendor_fields: dict = {}
        fields = apply_common_aliases(flat, vendor_fields, warnings)
        ts_raw = fields.pop("event_timestamp_raw", None)
        status = "success" if fields else "partial"
        if not fields:
            warnings.append("no recognizable fields found; all columns preserved as vendor_fields")

        return ParseResult(status=status, parser_name=self.name, parser_version=self.version,
                            fields=fields, vendor_fields=vendor_fields, warnings=warnings,
                            event_timestamp_raw=ts_raw)
