# Reserved standard fields — reference

This page is the single source of truth for the **31 reserved
standard fields** the audit library predeclares. These fields:

- Have library-fixed names. A taxonomy MUST NOT redeclare any of
  them as a custom field — the library rejects taxonomies that try.
- Have library-fixed Go types (`string`, `int`, `time.Time`).
  Generated builders enforce the type at the call site.
- Map to standard CEF extension keys (where one exists) so SIEM
  ingestions work out of the box without custom field mappings.
- Can carry sensitivity labels via the taxonomy `sensitivity_labels:`
  block. Labels apply per-output (strip / keep / transform).

If you need a field the library does not predeclare, use a custom
field — declare it in your taxonomy under
`events.<event_type>.fields:` (or use the catch-all `Fields` API).

## Framework fields vs reserved standard fields

Two distinct field categories have different semantics and
protections:

- **Framework fields** are always present in every emitted event
  and CANNOT be stripped by sensitivity labels. They are populated
  by the auditor itself (not by the consumer's code path):
  `timestamp`, `event_type`, `severity`, `event_category`,
  `app_name`, `host`, `pid`, `timezone`. (`duration_ms` is
  populated only on middleware-derived events.) See
  [`docs/json-format.md`](json-format.md) and
  [`docs/cef-format.md`](cef-format.md) for the framework-field
  contract.

- **Reserved standard fields** (this page) are *optional* per
  event but *predeclared* — if a consumer sets one, the library
  enforces the type and routes the value through any matching
  CEF mapping. Reserved standard fields CAN carry sensitivity
  labels and CAN be stripped per-output.

## The 31 reserved standard fields

All 31 fields are label-able (the generator emits a setter for every
one and the field can be excluded per-output via
`exclude_labels:`). The "Label-able" column is therefore omitted
from the table for compactness; should a future field be made
non-label-able, this column will be added.

| Field name | Go type | CEF extension key | Generated setter | Notes |
|---|---|---|---|---|
| `action` | `string` | — | `SetAction` | Verb / action name (e.g., `create`, `delete`, `read`). |
| `actor_id` | `string` | `suser` | `SetActorID` | Authenticated principal identifier (e.g., username). |
| `actor_uid` | `string` | `suid` | `SetActorUID` | OS-level / system UID of the actor. |
| `dest_host` | `string` | `dhost` | `SetDestHost` | Destination hostname. |
| `dest_ip` | `string` | `dst` | `SetDestIP` | Destination IP address. |
| `dest_port` | `int` | `dpt` | `SetDestPort` | Destination port (0–65535). |
| `end_time` | `time.Time` | `end` | `SetEndTime` | Operation end timestamp (paired with `start_time`). |
| `file_hash` | `string` | `fileHash` | `SetFileHash` | File-content hash (SHA-256 conventional). |
| `file_name` | `string` | `fname` | `SetFileName` | Basename only — strip the path. |
| `file_path` | `string` | `filePath` | `SetFilePath` | Absolute or relative path. |
| `file_size` | `int` | `fsize` | `SetFileSize` | File size in bytes. |
| `message` | `string` | `msg` | `SetMessage` | Human-readable summary. SHOULD be short and structured. |
| `method` | `string` | `requestMethod` | `SetMethod` | HTTP method (`GET`, `POST`, …). |
| `outcome` | `string` | `outcome` | `SetOutcome` | Convention: `success`, `failure`, `denied`. |
| `path` | `string` | `request` | `SetPath` | HTTP request path (no scheme/host). |
| `protocol` | `string` | `app` | `SetProtocol` | Application-layer protocol (`http`, `grpc`, `ssh`, …). |
| `reason` | `string` | `reason` | `SetReason` | Why an outcome occurred — especially for `denied`. |
| `referrer` | `string` | `requestContext` | `SetReferrer` | HTTP `Referer` header (note: HTTP misspelling preserved on the wire; field name uses correct spelling). |
| `request_id` | `string` | `externalId` | `SetRequestID` | Correlation ID for request → audit event. |
| `role` | `string` | `spriv` | `SetRole` | Actor's role / privilege at action time. |
| `session_id` | `string` | — | `SetSessionID` | Session correlator (per-actor session). |
| `source_host` | `string` | `shost` | `SetSourceHost` | Source hostname. |
| `source_ip` | `string` | `src` | `SetSourceIP` | Source IP address. |
| `source_port` | `int` | `spt` | `SetSourcePort` | Source port (0–65535). |
| `start_time` | `time.Time` | `start` | `SetStartTime` | Operation start timestamp. |
| `target_id` | `string` | `duser` | `SetTargetID` | Target principal identifier (the actor's *target*). |
| `target_role` | `string` | `dpriv` | `SetTargetRole` | Target's role / privilege. |
| `target_type` | `string` | — | `SetTargetType` | Type tag for the target (e.g., `user`, `bucket`, `secret`). |
| `target_uid` | `string` | `duid` | `SetTargetUID` | OS-level / system UID of the target. |
| `transport` | `string` | `proto` | `SetTransport` | Transport protocol (`tcp`, `udp`, `unix`). |
| `user_agent` | `string` | `requestClientApplication` | `SetUserAgent` | HTTP `User-Agent` header. |

All 31 fields can carry sensitivity labels (`sensitivity_labels:`
in the taxonomy) and can be stripped per-output via the
`exclude_labels:` list on the matching output config.

Three fields have no built-in CEF mapping (`action`,
`session_id`, `target_type`). When emitting CEF, the library
falls back to the field name itself as the extension key — these
land as custom CEF extensions if not overridden via
`CEFFormatter.FieldMapping`.

## Where these are defined

The single source of truth for the reserved-field contract is the
type map at the top of `std_fields.go`:

- **`std_fields.go`** — `reservedStandardFieldTypes` map; defines
  the 31 names + their Go types. `ReservedStandardFieldNames()`
  derives the canonical list from this map.
- **`format_cef.go`** — `defaultCEFFieldMappingEntries()` defines
  the 28 CEF extension key mappings (no entry → no built-in CEF
  mapping; falls back to the field name).
- **`cmd/audit-gen/`** — typed setters are emitted from the type
  map; setter naming follows `cmd/audit-gen/naming.go` (PascalCase
  with `Set…` prefix; the typed-setter feature itself dates to
  #575, where custom field setters gained correct Go types per
  YAML `type:` annotation — the `Set` prefix has been stable
  throughout).
- **`validate_taxonomy.go`** — `ReservedStandardFieldNames()`
  returns a sorted snapshot of the canonical list; taxonomies that
  redeclare any of these names are rejected at parse time.

## Maintainer checklist when adding a reserved field

When extending the reserved-field set:

1. Add the new name → type entry to `reservedStandardFieldTypes`
   in `std_fields.go`.
2. Add a CEF extension key mapping in
   `defaultCEFFieldMappingEntries()` (`format_cef.go`) if a
   standard CEF key applies. If the field has no clean CEF
   counterpart, omit the mapping — the field name is used as the
   extension key.
3. Update `TestReservedStandardFieldNames_Complete` in
   `taxonomy_test.go` to include the new name in its expected
   list. **This test is the integrity gate** — it WILL fail until
   updated, which forces every other touchpoint (including this
   doc) to be revisited.
4. **Update the table on this page**.
5. Generated setters are produced automatically by `cmd/audit-gen`
   from the type map — no manual code generation step required.
6. Mention the new field in `CHANGELOG.md` under `### Added`.

## See also

- [`docs/output-configuration.md`](output-configuration.md)
  `standard_fields:` section — YAML-side default values for
  reserved standard fields.
- [`docs/json-format.md`](json-format.md) — wire format for
  reserved standard fields under JSON output.
- [`docs/cef-format.md`](cef-format.md) — wire format under CEF
  output, including the extension keys above.
- [`docs/sensitivity-labels.md`](sensitivity-labels.md) — how to
  label reserved standard fields and exclude them per-output.
- `examples/05-standard-fields/` — runnable example demonstrating
  all 31 setters via the typed-builder API.
