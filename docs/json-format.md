[&larr; Back to README](../README.md)

# JSON Format

## What Is the JSON Format?

The JSON formatter serialises each audit event as a single line of
JSON — one event per line, no pretty-printing. This is the default
format used by audit. JSON output is designed for log aggregation
platforms (OpenSearch, Elasticsearch, Datadog, Loki, CloudWatch) and
for custom analytics pipelines that parse structured data.

For SIEM platforms (Splunk, ArcSight, QRadar), consider using the
[CEF format](cef-format.md) instead — SIEMs understand CEF natively
without custom field mapping.

## Example Output

```json
{"timestamp":"2026-01-15T10:30:00.123456789Z","event_type":"user_create","severity":5,"app_name":"my-service","host":"prod-01","timezone":"UTC","pid":12345,"actor_id":"alice","outcome":"success","target_id":"user-42","event_category":"write"}
```

> 💡 The `event_category` field is appended automatically when the
> event belongs to a category. It shows which category triggered
> this delivery. See [Taxonomy: Event Category](taxonomy-validation.md#event-category-in-output).

### Field Order

Fields are emitted in a deterministic order:

1. **Framework fields** (always first):
   - `timestamp` — event timestamp (RFC 3339 with nanoseconds by default)
   - `event_type` — the taxonomy event type name
   - `severity` — resolved severity (0-10)
   - `duration_ms` — only present if the event includes a duration
   - `app_name` — application name (required at construction via `WithAppName` or outputs YAML; `audit.New()` returns `ErrAppNameRequired` if unset)
   - `host` — hostname (required at construction via `WithHost` or outputs YAML; `audit.New()` returns `ErrHostRequired` if unset)
   - `timezone` — timezone name (always populated; auto-detected from system as `time.Now().Location().String()` when `WithTimezone` / outputs YAML is not provided)
   - `pid` — process ID (always present, auto-captured at auditor construction)

2. **Required fields** — sorted alphabetically
3. **Optional fields** — sorted alphabetically
4. **Extra fields** — any fields not declared in the taxonomy, sorted alphabetically
5. **`event_category`** — appended last, only for categorised events

This deterministic ordering makes JSON output diff-friendly and
predictable for downstream parsers.

## Configuration

### YAML

```yaml
# JSON is the default formatter. You only need a formatter block if
# you want to change the timestamp format or enable omit_empty.
outputs:
  audit_log:
    type: file
    file:
      path: "./audit.log"
    formatter:
      type: json                  # default if not specified
      timestamp: rfc3339nano      # default: "rfc3339nano" (or "unix_ms")
      omit_empty: false           # default: false
```

If you omit the `formatter` block entirely, JSON with `rfc3339nano`
timestamps and `omit_empty: false` is used.

### Timestamp Formats

| Value | Output | Example |
|-------|--------|---------|
| `rfc3339nano` (default) | RFC 3339 with nanoseconds | `"2026-01-15T10:30:00.123456789Z"` |
| `unix_ms` | Unix epoch milliseconds | `1737193800123` |

### OmitEmpty

When `omit_empty` is `true`, optional fields with zero values (`""`,
`0`, `nil`, `false`) are omitted from the output. This reduces payload
size but makes the JSON structure variable between events.

When `omit_empty` is `false` (default), all declared fields appear in
every event, with `null` for unset optional fields. This provides
structural consistency — every event of the same type has the same
set of keys.

## Further Reading

- [CEF Format](cef-format.md) — alternative format for SIEM integration
- [Progressive Example: Formatters](../examples/05-formatters/) — JSON and CEF side-by-side
- [API Reference: JSONFormatter](https://pkg.go.dev/github.com/axonops/audit#JSONFormatter)
