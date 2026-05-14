[← Back to examples](../README.md)

> **Previous:** [10 — Event Routing](../10-event-routing/) |
> **Next:** [12 — HMAC Integrity](../12-hmac-integrity/)
# Example 11: Sensitivity Labels

Strip sensitive fields from specific outputs: an internal log receives
all fields, a public analytics log has PII and financial data removed,
and a PCI compliance log keeps PII but strips payment card data.

## What You'll Learn

- Defining sensitivity labels in `taxonomy.yaml`
- Three mechanisms for labeling fields (explicit, global, regex)
- Configuring `exclude_labels` on outputs in `outputs.yaml`
- How field stripping works per-output
- Which fields are protected from stripping (framework fields)

## Prerequisites

- Go 1.26+
- Completed: [Event Routing](../10-event-routing/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Event definitions with sensitivity labels |
| `outputs.yaml` | Three outputs with different exclusion rules |
| `audit_generated.go` | Generated constants including `Label` constants |
| `main.go` | Emits events with sensitive fields, shows differential output |

## Key Concepts

### Why Sensitivity Labels?

Audit events often contain sensitive data — email addresses, phone
numbers, payment card numbers. Different outputs have different trust
levels:

- **Internal file log** — trusted, can receive everything
- **Analytics/SIEM** — less trusted, should not receive PII
- **PCI compliance log** — needs PII for investigations but must not
  contain payment card data

Without field-level filtering, you face a binary choice: send
everything everywhere (data leakage risk) or don't use certain outputs
(operational limitation). Sensitivity labels provide the middle ground.

### Defining Labels

Labels are defined in the `sensitivity:` section of your taxonomy YAML.
Each label has a name, optional description, and rules for which fields
carry it:

```yaml
sensitivity:
  labels:
    pii:
      description: "Personally identifiable information"
      fields: [email, phone]        # global field name mapping
      patterns: ["^user_"]          # regex pattern matching
    financial:
      description: "Financial and payment data"
      patterns: ["^card_"]          # any field starting with card_
```

### Three Labeling Mechanisms

There are three ways to associate a label with a field. All three are
additive — a field accumulates labels from every matching source.

**1. Global field name mapping** — any field with this exact name, in
any event, gets the label:

```yaml
sensitivity:
  labels:
    pii:
      fields: [email, phone]
```

Use this for field names that are consistently sensitive across your
application (e.g., `email` is always PII regardless of the event type).

**2. Regex pattern matching** — any field whose name matches the
pattern gets the label:

```yaml
sensitivity:
  labels:
    financial:
      patterns: ["^card_", "^account_"]
```

Use this for naming conventions (e.g., all fields starting with
`card_` are financial data).

**3. Explicit per-event annotation** — label a specific field on a
specific event:

```yaml
events:
  user_create:
    fields:
      user_name:
        labels: [pii]     # only on this event
```

Use this for one-off cases where a field is sensitive in one event
but not others.

### Field Declaration Syntax

Fields are declared in a `fields:` map on each event. Each field can
be:

| Syntax | Meaning |
|--------|---------|
| `field_name:` or `field_name: {}` | Optional, no labels |
| `field_name: {required: true}` | Required |
| `field_name: {labels: [pii]}` | Optional with sensitivity label |
| `field_name: {required: true, labels: [pii]}` | Required with label |

### Excluding Labels on Outputs

Each output can specify which labels to exclude. Fields carrying any
excluded label are stripped before the event reaches that output:

```yaml
outputs:
  public_log:
    type: file
    file:
      path: "./public-audit.log"
    exclude_labels:
      - pii
      - financial
```

If a field has labels `[pii, financial]` and the output excludes
`[pii]`, the field is stripped (any overlap is enough).

### Performance

Sensitivity labels add **zero allocation overhead**. Field exclusion
is handled inside the formatter's existing field iteration — excluded
fields are simply skipped during serialization, with no intermediate
map copies or temporary data structures. Outputs with exclusions use
the same number of allocations per event (5) as outputs without
exclusions. Defining sensitivity labels in your taxonomy but not
using `exclude_labels` on any output also has zero cost.

### Protected Framework Fields

Nine framework fields can never be labeled or stripped:

- `timestamp` — when the event occurred
- `event_type` — what happened
- `severity` — how important it is
- `duration_ms` — how long it took (middleware events)
- `event_category` — which category triggered delivery
- `app_name` — application identifier (required at construction; `audit.New()` returns `ErrAppNameRequired` if unset)
- `host` — hostname (required at construction; `audit.New()` returns `ErrHostRequired` if unset)
- `timezone` — timezone context (always populated; defaults to `time.Now().Location().String()` if `WithTimezone` is not provided)
- `pid` — process ID (always present)

These are always present in every output regardless of exclusion rules.
An event without `event_type` or `timestamp` would be unparseable.

### Generated Label Constants

When your taxonomy defines sensitivity labels, `audit-gen` generates
`Label` constants alongside the usual `Event`, `Category`, and `Field`
constants:

```go
const (
    LabelFinancial = "financial"
    LabelPii       = "pii"
)
```

These are useful when configuring exclusion labels programmatically
via `WithNamedOutput`.

### Generated Field-to-Label Mapping

`audit-gen` also generates a `FieldLabels` map showing which labels
each field carries after resolving all three mechanisms:

```go
var FieldLabels = map[string][]string{
    FieldCardExpiry: {LabelFinancial},
    FieldCardNumber: {LabelFinancial},
    FieldEmail:      {LabelPii},
    FieldPhone:      {LabelPii},
    FieldUserName:   {LabelPii},
}
```

This is useful for programmatic inspection — for example, masking
labeled fields in a debug UI or validating that your regex patterns
match the fields you expect.

### Emitting Events with Sensitive Fields

The generated typed builders make sensitivity visible in your code.
Setters for labeled fields include a godoc comment showing the label:

```go
// SetEmail sets the FieldEmail field.
// Sensitivity label: LabelPii — Personally identifiable information
func (e *UserCreateEvent) SetEmail(v any) *UserCreateEvent { ... }

// SetCardNumber sets the FieldCardNumber field.
// Sensitivity label: LabelFinancial — Financial and payment data
func (e *PaymentProcessEvent) SetCardNumber(v any) *PaymentProcessEvent { ... }
```

Using the builders to emit events with sensitive fields:

```go
if err := auditor.AuditEvent(NewUserCreateEvent("admin", "success").
    SetEmail("alice@example.com").
    SetPhone("555-0100").
    SetUserName("alice_smith").
    SetDepartment("engineering")); err != nil {
    log.Printf("audit error: %v", err)
}

if err := auditor.AuditEvent(NewPaymentProcessEvent("alice", "success").
    SetCardNumber("4111111111111111").
    SetCardExpiry("12/28").
    SetAmount("99.99")); err != nil {
    log.Printf("audit error: %v", err)
}
```

Required fields (`actorID`, `outcome`) are constructor parameters.
Sensitive optional fields (`email`, `phone`, `card_number`) use
chainable setters. The generated code handles field name mapping
internally — you never type `"email"` or `"card_number"` as raw
strings.

## Run It

```bash
go run .
```

## Expected Output

Three log files are created, each receiving the same events with
different field subsets:

```
INFO audit: auditor created queue_size=10000 shutdown_timeout=5s validation_mode=strict outputs=3 synchronous=false
INFO audit: shutdown started
INFO audit: shutdown complete duration=...

--- full-audit.log ---
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"admin","outcome":"success","department":"engineering","email":"alice@example.com","phone":"555-0100","user_name":"alice_smith","event_category":"write"}
{"timestamp":"...","event_type":"payment_process","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"alice","outcome":"success","amount":"99.99","card_expiry":"12/28","card_number":"4111111111111111","event_category":"write"}

--- public-audit.log ---
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"admin","outcome":"success","department":"engineering","event_category":"write"}
{"timestamp":"...","event_type":"payment_process","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"alice","outcome":"success","amount":"99.99","event_category":"write"}

--- pci-audit.log ---
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"admin","outcome":"success","department":"engineering","email":"alice@example.com","phone":"555-0100","user_name":"alice_smith","event_category":"write"}
{"timestamp":"...","event_type":"payment_process","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"alice","outcome":"success","amount":"99.99","event_category":"write"}
```

Notice:
- **full-audit.log** — all fields present (no exclusions)
- **public-audit.log** — `email`, `phone`, `user_name` (PII) and
  `card_number`, `card_expiry` (financial) are gone. Only
  `department` and `amount` remain as non-sensitive fields.
- **pci-audit.log** — `card_number` and `card_expiry` (financial)
  are stripped, but PII fields (`email`, `phone`, `user_name`) are
  preserved for security investigations

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `sensitivity label name must not be empty` | Label name is `""` | Use a non-empty name matching `[a-z][a-z0-9_]*` |
| `sensitivity label "X" does not match required pattern` | Uppercase or special characters | Use lowercase with underscores only |
| `sensitivity label "X" pattern "Y" is invalid` | Regex syntax error | Fix the regex pattern |
| `sensitivity label "X" pattern "Y" matches protected framework field "Z"` | Regex too broad | Narrow the regex to avoid matching framework fields (`timestamp`, `event_type`, `severity`, `duration_ms`, `event_category`, `app_name`, `host`, `timezone`, `pid`) |
| `event "X" field "Y" references undefined sensitivity label "Z"` | Label name typo | Check label is defined in `sensitivity.labels` |
| `output "X" has exclude_labels but taxonomy has no sensitivity config` | Missing `sensitivity:` block | Add `sensitivity:` to your taxonomy YAML |
| `output "X" exclude_labels references undefined sensitivity label "Z"` | Label name typo in output config | Check label is defined in taxonomy `sensitivity.labels` |

## Further Reading

- [Sensitivity Labels](../../docs/sensitivity-labels.md) — full label reference and regex patterns
- [Output Configuration YAML](../../docs/output-configuration.md) — exclude_labels syntax

