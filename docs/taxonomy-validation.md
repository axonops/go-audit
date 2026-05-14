[&larr; Back to README](../README.md)

# Taxonomy YAML Reference

The taxonomy is a single YAML file that defines your complete audit
event schema: which event types exist, what fields each requires,
how events are grouped into categories, and optionally how fields
are classified for sensitivity filtering.

This is a complete reference for everything that can go in a
`taxonomy.yaml` file.

## Why a Taxonomy?

Application logs are best-effort — a missing field doesn't break
anything. Audit logs are compliance artefacts. A security event
missing `actor_id` is useless for forensic investigation. A field
typo (`actorid` instead of `actor_id`) breaks SIEM parsing rules.

The taxonomy is a contract: "these are the audit events we produce,
and each one always includes these fields." The library validates
every event against this contract at runtime.

## Complete Schema

```yaml
version: 1

# Categories ──────────────────────────────────────────────
# Group related events. Used for per-output event routing.

categories:
  write:
    severity: 3                    # default severity for events in this category (0-10)
    events:
      - user_create
      - user_delete

  read:                            # categories can also be a simple list of event names
    - user_read
    - config_read

  security:
    severity: 8
    events:
      - auth_failure
      - auth_success

# Sensitivity Labels (optional) ──────────────────────────
# Classify fields by data sensitivity. Used with per-output
# exclude_labels to strip fields before delivery.

sensitivity:
  labels:
    pii:
      description: "Personally identifiable information"
      fields:                      # global field name mapping — any event with these fields
        - email
        - phone
      patterns:                    # regex patterns — matches field names across all events
        - "^user_"
    financial:
      description: "Financial and payment data"
      patterns:
        - "^card_"

# Events ──────────────────────────────────────────────────
# Define each audit event type and its fields.

events:
  user_create:
    description: "A new user account was created"   # used as CEF description header
    severity: 4                    # per-event severity override (takes priority over category)
    fields:
      outcome:
        required: true             # must be present in every event of this type
      actor_id:
        required: true
      email: {}                    # optional field — matched by pii.fields globally
      user_name:
        labels: [pii]             # explicit per-field sensitivity label annotation
      # target_id, reason, source_ip are reserved standard fields —
      # always available without declaration. Use SetTargetID(), etc.

  auth_failure:
    description: "An authentication attempt failed"
    fields:
      outcome:  { required: true }   # compact syntax
      actor_id: { required: true }
```

## Top-Level Fields

| Field | Required | Description |
|-------|----------|-------------|
| `version` | Yes | Must be `1`. Schema version for future migration. See [Taxonomy Schema Versioning](#taxonomy-schema-versioning) below. |
| `categories` | Yes | Map of category name to event list or struct. |
| `events` | Yes | Map of event type name to event definition. |
| `sensitivity` | No | Sensitivity label configuration for field classification. |

## Taxonomy Schema Versioning

The taxonomy YAML carries a top-level `version:` field so the
library can recognise the shape of the document and apply
migrations when a future schema change lands.

### What `version: 1` means today

`version: 1` is the only currently-defined schema version. Every
taxonomy MUST set `version: 1` explicitly:

```yaml
version: 1
categories:
  ...
events:
  ...
```

A missing or zero `version:` is rejected at parse time with:

```
audit: taxonomy validation failed: taxonomy version is required: set version to 1
```

A `version:` value the library does not recognise is rejected
with one of the two messages below, depending on whether the
value is from the future or from a no-longer-supported past:

```
audit: taxonomy validation failed: taxonomy version 2 is not supported by this library version (max: 1), upgrade the library
audit: taxonomy validation failed: taxonomy version 0 is no longer supported, minimum supported is 1
```

All three errors wrap the [`audit.ErrTaxonomyInvalid`](https://pkg.go.dev/github.com/axonops/audit#ErrTaxonomyInvalid)
sentinel; consumers can match with `errors.Is(err, audit.ErrTaxonomyInvalid)`
without coupling to the message text.

The parse path lives in [`audit.MigrateTaxonomy`](https://pkg.go.dev/github.com/axonops/audit#MigrateTaxonomy),
auto-invoked by [`audit.ParseTaxonomyYAML`](https://pkg.go.dev/github.com/axonops/audit#ParseTaxonomyYAML).

### Schema version is independent of library release version

The schema version (`version: 1` in YAML) is **not** the library
release version (e.g., v1.0.0, v1.5.0, v2.0.0). They evolve
independently:

- A v1.5 library MAY still use schema `version: 1` — operators
  upgrading the library do NOT need to touch their YAML.
- The schema version bumps only when the YAML shape itself
  changes in a way that older libraries cannot interpret (new
  required field, removed field, or restructured nesting). This
  is a maintainer-side decision; consumers do not need to touch
  the version field on routine library upgrades.
- A library release version bumps for any release reason — bug
  fix, new feature, performance improvement — even when the
  schema is unchanged.

For the lifetime of v1.x of the library, `version: 1` will remain
accepted. Schema-breaking changes are themselves library-major
events: a `version: 2` schema would land in v2.x of the library
(or earlier, with `version: 1` still accepted alongside it).

### Future migration contract

When `version: 2` is introduced, the library will:

1. Accept both `version: 1` and `version: 2` configs side-by-side
   for at least one tagged library release; the deprecation
   timeline for `version: 1` will be announced via the
   `CHANGELOG.md` `### Deprecated` section.
2. Silently upgrade `version: 1` configs to the new internal
   shape — operators do not need to rewrite their YAML.
3. Reject `version: N+1` from a library that only knows up to
   `N`, with a clear "upgrade the library" error (the message
   above).
4. Reject `version: K-M` once support for `K-M` is dropped, with
   a clear "no longer supported, minimum supported is N" error
   that names the lowest still-accepted version.

Migrations land inline inside `MigrateTaxonomy` — the function
already has the structure (version check, future migration
hook). There is no public `RegisterMigration` API today, by
design: migrations are library-implementation detail, not a
consumer extension point.

### When the maintainer adds `version: 2`

The schema-bump workflow is:

1. Bump `currentTaxonomyVersion` in `migrate.go` and add a
   migration step (`if t.Version == 1 { ... }`) that
   transforms the old shape into the new one.
2. Update the YAML examples under `examples/`,
   `tests/bdd/features/`, and `outputconfig/testdata/` to use the
   new version where appropriate (keeping at least one
   `version: 1` example to lock the migration path).
3. Add a regression BDD scenario that loads a `version: 1`
   document, runs migration, and asserts the in-memory shape
   matches a hand-written `version: 2` equivalent.
4. Update this section with the new version literal and the
   shape change.

## Categories

Categories group related events. Each category supports two equivalent
forms — both parse to the same internal representation, and mixing
forms within a taxonomy MUST NOT change the resolved severity, the
event-to-category mapping, or any other observable behaviour.

### Expanded form (preferred style)

The expanded form is RECOMMENDED when any category in your taxonomy
uses a default severity — keeping every category in the same shape
makes the severity intent visible at a glance. Examples in this
repository (root `README.md`,
`examples/02-code-generation/taxonomy.yaml`) all use the expanded form:

```yaml
categories:
  security:
    severity: 8
    events:
      - auth_failure
      - auth_success
```

### Compact form (shorthand)

When a category does not need a default severity, the compact form is
a flat list of event names — equivalent to the expanded form with no
`severity` key:

```yaml
categories:
  read:
    - user_read
    - config_read
```

The two forms are interchangeable. The compact form is purely a
shorthand: `read: [user_read, config_read]` parses identically to
`read: { events: [user_read, config_read] }` (severity defaults to
`5` when not set at either category or event level).

Both forms may be mixed within the same taxonomy, but using one form
consistently makes the file easier to skim.

An event can belong to multiple categories. Events not in any
category are valid and always globally enabled.

## Events

Each event defines its description, optional severity override, and
fields:

```yaml
events:
  user_create:
    description: "A new user account was created"
    severity: 4            # optional — overrides category severity
    fields:
      outcome:
        required: true     # this field must be present
      actor_id:
        required: true
      email: {}            # optional field
      user_name:
        labels: [pii]     # optional field with sensitivity label
```

| Event Field | Required | Description |
|-------------|----------|-------------|
| `description` | No | Human-readable label. Used as CEF description header. |
| `severity` | No | Per-event severity (0-10). Overrides category severity. |
| `fields` | No | Map of field name to field definition. If omitted, the event accepts only framework fields in strict mode. |

### Field Definitions

Fields can be defined in three ways:

```yaml
fields:
  outcome:                 # expanded — required field
    required: true
  actor_id:                # expanded — required field with label
    required: true
    labels: [pii]
  email: {}                # compact — optional field, no labels
  user_name:               # expanded — optional field with label
    labels: [pii]
  custom_field: {}         # compact — optional, no labels
  notes:                   # bare — same as {}
  quota:                   # typed custom field — generates SetQuota(v int)
    type: int
  created_at:
    type: time             # generates SetCreatedAt(v time.Time)
```

| Field Property | Default | Description |
|----------------|---------|-------------|
| `required` | `false` | If `true`, the library rejects events missing this field. |
| `labels` | `[]` | List of sensitivity label names applied to this field. |
| `type` | `string` | Go type emitted by [audit-gen] in the typed setter for this custom field. Accepts `string`, `int`, `int64`, `float64`, `bool`, `time` (→ `time.Time`), `duration` (→ `time.Duration`). Reserved standard fields (`actor_id`, `source_ip`, etc.) reject `type:` — their Go type is library-authoritative. Unknown values are rejected at parse time. |

## Sensitivity Labels

Sensitivity labels classify fields by data sensitivity. There are
three ways to assign labels to fields:

### 1. Explicit per-field annotation

Directly on the field definition in the event:

```yaml
events:
  user_create:
    fields:
      user_name:
        labels: [pii]     # this specific field in this event
```

### 2. Global field name mapping

Any field with this name in any event gets the label:

```yaml
sensitivity:
  labels:
    pii:
      description: "Personally identifiable information"
      fields:
        - email            # every event with an "email" field
        - phone            # every event with a "phone" field
```

### 3. Regex patterns

Any field name matching the pattern in any event gets the label:

```yaml
sensitivity:
  labels:
    financial:
      description: "Financial and payment data"
      patterns:
        - "^card_"         # matches card_number, card_expiry, etc.
```

All three mechanisms are resolved at taxonomy parse time — there is
no per-event runtime cost. Labels from all three sources are additive.

Per-output field stripping is configured in `outputs.yaml`, not in
the taxonomy. See [Sensitivity Labels](sensitivity-labels.md) and
[Outputs](outputs.md) for the `exclude_labels` configuration.

## Name Character Set and Length

Every consumer-controlled taxonomy identifier — category name, event
type key, required/optional field name, and sensitivity label name —
must match this pattern:

```
^[a-z][a-z0-9_]*$
```

That is: start with a lowercase letter, followed by lowercase letters,
digits, or underscores only. Names are additionally capped at **128
bytes**.

Rejected examples:

| Name | Reason |
|------|--------|
| `UserCreate` | uppercase letter |
| `user-create` | hyphen |
| `user.create` | dot |
| `user create` | space |
| `1create` | starts with digit |
| `_create` | starts with underscore |
| `user\u202eadmin` | bidi override character |
| `user` + 129 bytes | exceeds 128-byte cap |

### Why this is enforced

The pure-ASCII rule keeps the following out of downstream log
consumers, SIEM dashboards, and error messages:

- **Bidi override characters** (U+202E, U+2066-2069) that could
  reorder terminal output (CVE-2021-42574 class).
- **Unicode confusables** — Cyrillic `а` (U+0430) vs ASCII `a`, Greek
  omicron (U+03BF) vs `o`, full-width letters (U+FF21-FF5A), etc.
- **CEF metacharacters** (`|`, `=`, `\`, `"`) that would corrupt CEF
  header or extension parsing.
- **C0/C1 control bytes** (0x00-0x1F, 0x7F, 0x80-0x9F) that could
  embed ANSI escape sequences, cursor manipulation, or NUL-injection
  into log lines.
- **Length DoS** — a multi-kilobyte identifier blown through every
  log line.

When a name fails either check, `ValidateTaxonomy` returns an error
that wraps both [`ErrTaxonomyInvalid`](error-reference.md#errtaxonomyinvalid)
and [`ErrInvalidTaxonomyName`](error-reference.md#errinvalidtaxonomyname),
so consumers can discriminate name-shape violations from other
taxonomy errors:

```go
tax, err := audit.ParseTaxonomyYAML(data)
if errors.Is(err, audit.ErrInvalidTaxonomyName) {
    // bad name — fix the YAML
}
if errors.Is(err, audit.ErrTaxonomyInvalid) {
    // any taxonomy validation failure, including the above
}
```

Error messages render the offending name through `%q`, so control
bytes and bidi characters appear as Go escape sequences
(`\x00`, `\u202e`) rather than as raw bytes that could hijack
terminal output.

The same rule is enforced by the `cmd/audit-gen` code generator — a
malformed name causes codegen to fail before any Go source is written,
preventing a "generates fine, never loads at runtime" trap.

## Reserved Field Names

The following field names are managed by the framework and cannot be
used as required or optional fields in your taxonomy:

| Field | Purpose |
|-------|---------|
| `timestamp` | Event timestamp, set by the drain goroutine |
| `event_type` | Event type name from the taxonomy |
| `severity` | Resolved severity (0-10) |
| `event_category` | Delivery-specific category (see below) |
| `app_name` | Application name (set via outputs YAML or `WithAppName`) |
| `host` | Hostname (set via outputs YAML or `WithHost`) |
| `timezone` | Timezone context (set via outputs YAML or `WithTimezone`) |
| `pid` | Process ID (auto-captured at construction) |
| `_hmac` | HMAC integrity signature (set by HMAC config) |
| `_hmac_version` | HMAC salt version (set by HMAC config) |

If you try to define any of these as a required or optional field,
taxonomy validation fails with:

```
event "auth.login" field "event_category" is a reserved framework field
```

> 💡 `duration_ms` is a framework field for sensitivity protection
> but is NOT reserved — it can be used as an optional field because
> the HTTP middleware legitimately sets it as a user-provided value.

## Event Category in Output

When an event belongs to a category, the `event_category` field is
automatically appended to the serialised output (JSON and CEF). This
tells downstream consumers (SIEMs, log aggregators) which category
triggered the delivery.

### Configuration

```yaml
categories:
  emit_event_category: true    # default: true (can be omitted)
  security:
    events: [auth_failure]
```

| Setting | Behaviour |
|---------|-----------|
| Absent from YAML | `event_category` is appended (default: true) |
| `emit_event_category: true` | `event_category` is appended |
| `emit_event_category: false` | `event_category` is never appended, zero overhead |

### Output Examples

**JSON:**
```json
{"timestamp":"...","event_type":"auth_failure","severity":8,"outcome":"failure","event_category":"security"}
```

**CEF:**
```
CEF:0|...|auth_failure|...|8|... outcome=failure cat=security
```

### Multi-Category Events

Events in multiple categories produce separate deliveries, each with
a different `event_category` value. The base event data is serialised
once (cached); only the appended category differs per delivery.

### Uncategorised Events

Events not in any category do not include `event_category` in the
output — the field is omitted entirely (not null, not empty string).

## Severity Resolution

Severity is a 0-10 scale used in CEF output and event routing.
Resolution order:

1. Per-event `severity` (highest priority)
2. Category `severity`
3. Default: `5`

See [CEF Format — Severity Levels](cef-format.md#severity-levels)
for practical guidance on choosing severity values.

## Validation Modes

| Mode | Behaviour |
|------|-----------|
| `strict` (default) | Rejects events with fields not declared in the taxonomy or with unsupported value types |
| `warn` | Accepts unknown fields and unsupported value types; logs a warning via `log/slog` and coerces unsupported values to string |
| `permissive` | Accepts any fields without warning; silently coerces unsupported values to string |

Set via `audit.WithValidationMode(audit.ValidationWarn)` on
`New`, the `validation_mode` key in your outputs YAML, or
`audittest.WithValidationMode(audit.ValidationWarn)` in tests.

## Supported Field Value Types

`audit.Fields` accepts `map[string]any`, but only this set of value
types is guaranteed to render faithfully across both the JSON and
CEF formatters:

| Type | Example |
|------|---------|
| `string` | `"alice"` |
| `int`, `int32`, `int64` | `8080` |
| `float64` | `1.5` |
| `bool` | `true` |
| `time.Time` | `time.Now().UTC()` |
| `time.Duration` | `5 * time.Second` |
| `[]string` | `[]string{"admin", "auditor"}` |
| `map[string]string` | `map[string]string{"k": "v"}` |
| `nil` | rendered as `null` (JSON) or absent (CEF) |

Behaviour for values **outside** this vocabulary depends on the
auditor's `ValidationMode`:

| Mode | Outcome |
|------|---------|
| `strict` | `Auditor.AuditEvent` returns `*audit.ValidationError` wrapping `audit.ErrUnknownFieldType`; the event is dropped. |
| `warn` | The unsupported value is coerced via `fmt.Sprintf("%v", v)` and a `log/slog` warning is emitted. |
| `permissive` | The unsupported value is coerced silently. |

Coercion produces formatter-hostile output for composite types
(struct dumps, `{}` for empty maps). Pass values from the supported
vocabulary; the validation mode is a backstop, not a feature.

### Reserved standard field types

Reserved standard fields carry an additional declared Go type for
type-aware tooling and `WithStandardFieldDefaults` validation. Query
the type at runtime:

```go
t, ok := audit.ReservedStandardFieldType("source_port")
// t == audit.ReservedFieldInt
```

Most reserved fields are `string`; `source_port`, `dest_port`, and
`file_size` are `int`; `start_time` and `end_time` are `time.Time`.
See the `ReservedFieldType` enum in the godoc for the complete list.

`audit.WithStandardFieldDefaults(map[string]any{...})` rejects
deployment-time defaults whose Go type does not match the declared
reserved-field type. The error wraps `audit.ErrConfigInvalid` and
surfaces at `audit.New` time, before any event is processed.

## Prototyping with DevTaxonomy

[`audit.DevTaxonomy`](https://pkg.go.dev/github.com/axonops/audit#DevTaxonomy)
is a permissive taxonomy for prototyping. It accepts any event
type with any fields, places every event into a single "dev"
category, and emits a runtime warning so the trade-off is visible
in logs.

```go
auditor, _ := audit.New(
    audit.WithTaxonomy(audit.DevTaxonomy("user_login", "user_logout")),
    audit.WithAppName("prototype"),
    audit.WithHost("dev"),
    audit.WithOutputs(stdoutOut),
)
```

DevTaxonomy is **not for production**. It bypasses every schema
guarantee the library provides: typos in event names, unknown
fields, missing required fields — all accepted without error.

### Migrating from DevTaxonomy to a strict taxonomy

The migration is a four-step swap:

```go
// BEFORE — prototype
auditor, _ := audit.New(
    audit.WithTaxonomy(audit.DevTaxonomy("user_login", "user_logout")),
    // ...
)

// AFTER — production
//go:embed taxonomy.yaml
var taxonomyYAML []byte

tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
if err != nil { /* handle */ }
auditor, _ := audit.New(
    audit.WithTaxonomy(tax),
    // ...
)
```

1. **Enumerate event sites.** Grep for every `audit.NewEvent(`,
   `auditor.AuditEvent(`, and any generated event-builder
   constructor names (`NewUserLoginEvent(...)` etc.). The
   DevTaxonomy warning does not flag stale call sites — strict
   validation does, at first event.
2. **Author the YAML.** For each event type, declare its required
   fields, category, and severity. See [Events](#events) and
   [Severity Resolution](#severity-resolution) for the schema.
3. **Swap the constructor.** Replace
   `audit.WithTaxonomy(audit.DevTaxonomy(...))` with
   `audit.WithTaxonomy(parsedTaxonomy)`. The first event after
   swap will surface `audit: unknown event type` for any
   leftover site.
4. **Optionally regenerate.** Run `audit-gen` to produce typed
   event builders (see [examples/02-code-generation](../examples/02-code-generation/));
   the schema is then enforced at compile time, not just runtime.

## Loading a Taxonomy

The library accepts `[]byte` only — not file paths. Use `go:embed`
to bundle the YAML into your binary:

```go
//go:embed taxonomy.yaml
var taxonomyYAML []byte

tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
```

**Constraints:**
- The input must be a single YAML document. Multi-document YAML
  (separated by `---`) is rejected.
- Unknown YAML keys are rejected. A typo like `sevrity` instead
  of `severity` produces a parse error, not a silently ignored field.

## Size and Scale

`ParseTaxonomyYAML` imposes **no input-size cap**. The taxonomy is
developer-owned input — typically embedded at compile time via
`embed.FS` or loaded from a file path the developer controls — so
the library treats the document as trusted. A YAML alias bomb
amplifies regardless of input size; bounding the byte length would
not defend against amplification, and `goccy/go-yaml` does not
expose an alias-budget guard. The cap was retired in #646.

Memory usage scales linearly with the number of event types, field
definitions, and sensitivity patterns. There is no fixed ceiling —
a large enterprise taxonomy with thousands of microservice event
types loads correctly.

**Parse-time cost.** Sensitivity precompute is
O(events × fields × labels × patterns): taxonomies that combine
many events, many fields per event, AND many sensitivity patterns
will see noticeable parse-time cost. This is a one-shot cost paid
at `ParseTaxonomyYAML` time; the precomputed `*Taxonomy` is then
consulted in O(1) on the audit hot path. Operators running
`audit-validate` against very large CI-supplied taxonomies should
ensure their CI sandbox has a memory limit configured.

**Outputs YAML is a different surface.** The
`outputconfig.MaxOutputConfigSize` cap on `outputs.yaml` (1 MiB)
remains in place — outputs config is ops-controlled (Kubernetes
ConfigMap, env-substituted templates) and crosses a different trust
boundary.

## Further Reading

- [Progressive Example: Basic](../examples/01-basic/) — inline taxonomy
- [Progressive Example: Code Generation](../examples/02-code-generation/) — YAML taxonomy with audit-gen
- [Sensitivity Labels](sensitivity-labels.md) — per-output field stripping
- [CEF Format](cef-format.md) — severity levels and SIEM integration
- [API Reference: ParseTaxonomyYAML](https://pkg.go.dev/github.com/axonops/audit#ParseTaxonomyYAML)
