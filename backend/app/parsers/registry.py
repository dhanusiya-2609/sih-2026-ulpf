"""
Parser registry: a lightweight plugin system. Parsers register themselves
here; new formats can be added by implementing BaseParser and adding one
line to `_all_parsers()` without touching the rest of the pipeline (routes,
normalization, storage all depend only on this registry's interface).
"""
from .base import BaseParser, ParseResult
from .json_parser import JSONParser
from .csv_parser import CSVParser
from .xml_parser import XMLParser
from .cef_parser import CEFParser
from .leef_parser import LEEFParser
from .syslog_parser import SyslogParser
from .kv_parser import KVParser
from .generic_parser import GenericFallbackParser

DETECTION_THRESHOLD = 0.5


def _all_parsers() -> list[BaseParser]:
    # Order matters as a tie-breaker only; detect() confidence decides first.
    return [
        CEFParser(),
        LEEFParser(),
        JSONParser(),
        XMLParser(),
        SyslogParser(),
        CSVParser(),
        KVParser(),
        GenericFallbackParser(),
    ]


class ParserRegistry:
    def __init__(self):
        self._parsers: dict[str, BaseParser] = {p.name: p for p in _all_parsers()}

    def get(self, name: str) -> BaseParser | None:
        return self._parsers.get(name)

    def list_parsers(self) -> list[BaseParser]:
        return list(self._parsers.values())

    def detect_best(self, raw_text: str) -> BaseParser:
        best = None
        best_score = -1.0
        for p in self._parsers.values():
            try:
                score = p.detect(raw_text)
            except Exception:
                score = 0.0
            if score > best_score:
                best = p
                best_score = score
        if best is None or best_score < DETECTION_THRESHOLD:
            return self._parsers["generic_fallback_parser"]
        return best

    def parse(self, raw_text: str, forced_parser_name: str | None = None) -> ParseResult:
        """
        Parse never raises: any internal parser exception is caught here and
        converted into a 'failed'->fallback result so one bad log line can
        never take down the ingestion pipeline (AC-10).
        """
        parser = None
        if forced_parser_name:
            parser = self.get(forced_parser_name)
        if parser is None:
            try:
                parser = self.detect_best(raw_text)
            except Exception:
                parser = self._parsers["generic_fallback_parser"]

        try:
            result = parser.parse(raw_text)
        except Exception as e:
            result = ParseResult(
                status="failed", parser_name=parser.name, parser_version=parser.version,
                warnings=[f"parser raised an unexpected exception: {e}"],
            )

        if result.status == "failed" and parser.name != "generic_fallback_parser":
            # Degrade gracefully to the fallback parser rather than losing the event.
            fallback = self._parsers["generic_fallback_parser"]
            fb_result = fallback.parse(raw_text)
            fb_result.warnings.insert(
                0, f"primary parser '{parser.name}' failed: {'; '.join(result.warnings) or 'unknown error'}"
            )
            return fb_result

        return result


registry = ParserRegistry()
