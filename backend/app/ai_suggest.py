"""
AI-assisted parser onboarding support.

IMPORTANT / honesty constraints (per problem statement section G):
- Suggestions here are advisory only; they are never auto-applied or
  auto-executed. A human must review and approve a mapping before it is
  used for future events (see TrainingRecord.status).
- The DEFAULT suggestion engine is a deterministic, offline heuristic
  (string-similarity + regex field detection). It requires no network
  access, no GPU, and no commercial API key, satisfying the air-gapped and
  "no paid LLM required" requirements.
- An OPTIONAL local LLM adapter hook is provided below (`LocalLLMAdapter`)
  for sites that have a locally hosted open-source model available. It is
  disabled by default. If unavailable or unconfigured, the system
  transparently falls back to the deterministic heuristic -- it never
  blocks onboarding on the AI being present.
- Saving an approved mapping is a configuration/rule-save operation, NOT
  model training. No model weights are altered by this feature.
"""
import difflib
import os
import re
from typing import Optional

TARGET_SCHEMA_FIELDS = [
    "network.source_ip", "network.destination_ip", "network.source_port",
    "network.destination_port", "network.protocol", "network.transport",
    "event.action", "event.severity", "event.category", "event.type", "event.outcome",
    "source.device_name", "source.vendor", "source.source_ip",
    "event_timestamp", "message",
]

_ALIAS_HINTS = {
    "network.source_ip": ["src", "srcip", "source_ip", "saddr", "sip", "from"],
    "network.destination_ip": ["dst", "dstip", "destination_ip", "daddr", "dip", "to"],
    "network.source_port": ["sport", "srcport", "spt"],
    "network.destination_port": ["dport", "dstport", "dpt"],
    "network.protocol": ["proto", "protocol", "ipproto"],
    "event.action": ["action", "verdict", "disposition", "act"],
    "event.severity": ["severity", "level", "sev", "pri"],
    "source.device_name": ["host", "hostname", "device", "devname", "dvchost"],
    "event_timestamp": ["time", "date", "timestamp", "eventtime"],
}


def _score_field_name(candidate: str, target: str) -> float:
    candidate = candidate.lower()
    best = 0.0
    for hint in _ALIAS_HINTS.get(target, []):
        ratio = difflib.SequenceMatcher(None, candidate, hint).ratio()
        if hint in candidate or candidate in hint:
            ratio = max(ratio, 0.85)
        best = max(best, ratio)
    return best


def heuristic_suggest(sample_fields: dict) -> dict:
    """Given a flat dict of {source_field_name: example_value}, suggest a
    mapping {source_field_name: target_schema_path} using string-similarity
    matching against known alias hints. Confidence < 0.55 is omitted so we
    do not suggest low-quality guesses as if confident."""
    suggestions = {}
    for field_name, value in sample_fields.items():
        best_target, best_score = None, 0.0
        for target in TARGET_SCHEMA_FIELDS:
            score = _score_field_name(field_name, target)
            if score > best_score:
                best_target, best_score = target, score
        # Light value-shape sanity check for IP-looking fields
        if best_target in ("network.source_ip", "network.destination_ip") and value:
            if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(value)):
                best_score *= 0.6
        if best_target and best_score >= 0.55:
            suggestions[field_name] = {"target": best_target, "confidence": round(best_score, 2)}
    return suggestions


class LocalLLMAdapter:
    """
    Optional adapter for a locally hosted open-source model (e.g. an
    Ollama/llama.cpp endpoint on localhost). Disabled unless
    ULPF_LOCAL_LLM_URL is set, so the platform's core functionality never
    depends on it. Not wired to any commercial/cloud API.
    """
    def __init__(self):
        self.endpoint = os.environ.get("ULPF_LOCAL_LLM_URL")  # e.g. http://localhost:11434
        self.available = bool(self.endpoint)

    def suggest(self, sample_fields: dict) -> Optional[dict]:
        if not self.available:
            return None
        # Left intentionally unimplemented in this prototype: wiring a real
        # local model call here is a documented extension point. Returning
        # None triggers the deterministic fallback so nothing breaks if a
        # user sets the env var without actually running a local model.
        return None


def suggest_mapping(sample_fields: dict) -> tuple[dict, str]:
    """Returns (suggestions, suggestion_source)."""
    llm = LocalLLMAdapter()
    llm_result = llm.suggest(sample_fields)
    if llm_result is not None:
        return llm_result, "local_llm"
    return heuristic_suggest(sample_fields), "heuristic"
