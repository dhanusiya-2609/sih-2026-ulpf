# ULPF Architecture

## 1. Goal and shape of the system

ULPF takes logs from heterogeneous, vendor-specific sources and turns them
into one normalized, queryable, exportable stream — without ever discarding
the original. The design has one central rule that shapes everything else:

> **Raw preservation and normalization are separate concerns, and the
> pipeline that does both is the same regardless of how an event arrived.**

That rule is why `app/ingestion/pipeline.py` exists as a single function
(`process_single_event`) called by the file-upload path, the UDP listener,
and the TCP listener alike. There is exactly one place where "store the raw
bytes, then try to understand them" happens, so a guarantee added there
(e.g. "never crash on malformed input") holds everywhere automatically
instead of needing to be re-implemented per ingestion method.

## 2. Data flow

```
                          ┌─────────────────────────┐
  File upload  ────────►  │                         │
  UDP syslog   ────────►  │   process_single_event  │
  TCP syslog   ────────►  │                         │
                          └───────────┬─────────────┘
                                      │
                     1. RawEvent stored verbatim + SHA-256 hash
                                      │
                     2. ParserRegistry.parse(raw_text)
                        - tries each parser's detect() for a confidence
                          score, runs the highest scorer's parse()
                        - never raises: any exception, or a parser
                          reporting "failed", falls back to the generic
                          parser so the event is never lost
                                      │
                     3. normalize(parse_result, source_metadata)
                        - maps parser-specific field names onto the
                          common intermediate keys (source_ip, action, ...)
                        - parses timestamps best-effort, flags uncertainty
                        - downgrades status to "partial" if nothing
                          meaningful was actually extracted
                                      │
                     4. NormalizedEvent stored, linked to RawEvent by ID
                     5. JSON-Schema validation pass (warnings recorded,
                        never blocks storage of the raw event)
                                      │
                                      v
                     REST API (search/export/detail) -- Web console
```

## 3. Component responsibilities

- **Parsers** (`app/parsers/*.py`) - one class per format, implementing
  `detect(text) -> confidence` and `parse(text) -> ParseResult`. Each is
  independent and self-contained; adding a new vendor format that doesn't
  fit an existing family means adding one new file and one line in
  `registry.py`, touching nothing else.
- **Registry** (`app/parsers/registry.py`) - auto-detection by highest
  confidence score, with a hard fallback to the generic parser on any
  exception or explicit "failed" status. This is the single place the
  "never crash the pipeline" guarantee is enforced.
- **Normalization** (`app/normalization.py`) - the only place that knows
  about the *common* schema. Parsers never write directly to schema field
  names; they emit intermediate keys, and normalization does the mapping,
  timestamp parsing, and severity-scale reconciliation (syslog's 0-7 PRI
  scale vs. CEF's 0-10 scale both become the same small vocabulary of
  words: low/medium/high/critical or emergency/alert/.../debug).
- **Models** (`app/models.py`) - `RawEvent` and `NormalizedEvent` are
  separate tables linked by foreign key, not one merged row, so "what did
  we actually receive" and "what we think it means" can never be
  conflated or accidentally overwritten by a re-parse.
- **API** (`app/api/*.py`) - one router module per resource area (sources,
  ingestion, events, dashboard, export, parsers, training/onboarding,
  alerts, misc/settings). Auth and RBAC are FastAPI dependencies
  (`get_current_user`, `require_role(...)`), applied per-route rather than
  globally, so read endpoints stay open to any authenticated role while
  destructive operations and raw-log access are gated.
- **Redaction** (`app/redaction.py`) - a presentation-layer pass applied
  when building API/export responses. It never touches the stored
  `RawEvent.raw_message`; it masks configured sensitive field names in
  `vendor_fields` and matching `key=value` patterns in free-text messages.
- **Web console** (`app/static/`) - plain HTML/CSS/JS, no build step, no
  external CDN dependency (system font stacks only), so it renders
  identically in an air-gapped deployment. Each page is a thin client over
  the REST API; there is no server-side templating or duplicated business
  logic between frontend and backend.

## 4. Why a common intermediate representation, not schema-per-vendor

Parsers emit a small, fixed set of intermediate keys (`source_ip`,
`destination_ip`, `action`, `severity`, `protocol`, ...) regardless of
whether the source called it `src`, `srcip`, or `src_ip`. Normalization
then does one alias-resolution pass. This means: (a) a new vendor format
only needs to map its field names onto the *existing* intermediate
vocabulary, not invent new schema paths; (b) the common schema
(`event_schema.json`) stays stable and versioned independent of how many
parsers exist; (c) anything a parser can't confidently map is preserved
untouched in `vendor_fields` rather than silently dropped.

## 5. Deployment model

SQLite by default - the entire system runs as a single container with no
external database dependency, which matters for the air-gapped/offline
requirement. `ULPF_DATABASE_URL` swaps to PostgreSQL for a
multi-instance/production deployment without any code change (SQLAlchemy
abstracts the difference; Alembic migrations run against either). Schema
changes are managed by Alembic (`backend/migrations/`), applied
automatically by `docker-entrypoint.sh` before the server starts.

## 6. Known architectural trade-offs

- **Pipeline runs synchronously in the request/listener thread.** For a
  prototype at demo scale this is simpler to reason about and test; a
  production deployment ingesting at high sustained volume would want to
  put `process_single_event` behind a queue (the event lands in a durable
  queue immediately, a worker pool calls the same pipeline function
  asynchronously) rather than parsing inline. The function boundary is
  already there to make that change localized.
- **UDP has no delivery guarantee**, by protocol design, not by omission
  here - the dashboard reports received/malformed counters as best-effort
  observability rather than pretending completeness.
