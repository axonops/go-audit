[&larr; Back to README](../README.md)

# Sensitivity Labels

- [What Are Sensitivity Labels?](#what-are-sensitivity-labels)
- [Why Sensitivity Labels?](#why-sensitivity-labels)
- [Taxonomy Configuration](#taxonomy-configuration)
- [Per-Output Exclusion](#per-output-exclusion)
- [Protected Fields](#protected-fields)

## What Are Sensitivity Labels?

Sensitivity labels classify audit event fields by their data
sensitivity — for example, `pii` (personally identifiable information),
`financial` (payment data), or `internal` (internal-only data). Labels
are defined in the taxonomy and applied to fields. Each output can then
exclude specific labels, stripping sensitive fields before delivery.

## Why Sensitivity Labels?

Audit events often contain sensitive data that must be handled
differently depending on the destination:

- **Internal compliance file** — needs the complete audit trail, including PII
- **External SIEM** — must NOT receive PII fields (GDPR, CCPA compliance)
- **Alerting webhook** — must NOT receive financial data (PCI-DSS)

Without sensitivity labels, you would need to maintain separate event
definitions or manually filter fields per output. Sensitivity labels
let you define the classification once in your taxonomy and apply
per-output stripping rules in configuration.

## Taxonomy Configuration

```yaml
sensitivity:
  labels:
    pii:
      description: "Personally identifiable information"
      fields:        # global field name mapping
        - email
        - phone
      patterns:      # regex patterns for field matching
        - "^user_"
    financial:
      description: "Financial and payment data"
      patterns:
        - "^card_"

events:
  user_create:
    fields:
      actor_id:
        required: true
      email: {}                     # matched by pii.fields
      user_name:
        labels: [pii]              # explicit per-field annotation
      card_number: {}              # matched by financial.patterns
```

### Three Labeling Mechanisms

| Mechanism | Scope | Example |
|-----------|-------|---------|
| **Explicit annotation** | Per-field in event definition | `user_name: {labels: [pii]}` |
| **Global field mapping** | Any event with that field name | `fields: [email, phone]` under the label |
| **Regex patterns** | Any field name matching the pattern | `patterns: ["^card_"]` under the label |

All three mechanisms are resolved at taxonomy parse time — there is no
per-event runtime cost for label resolution.

## Per-Output Exclusion

```yaml
outputs:
  internal_file:
    type: file
    file:
      path: "/var/log/audit/full.log"
    # no exclude_labels — receives all fields

  external_siem:
    type: syslog
    syslog:
      address: "syslog.example.com:514"
    exclude_labels: [pii]
    # email, phone, user_name stripped before delivery

  payment_alerts:
    type: webhook
    webhook:
      url: "https://alerts.example.com/audit"
    exclude_labels: [pii, financial]
    # email, phone, user_name, card_number, card_expiry stripped
```

## Protected Fields

Framework fields are never stripped, regardless of label configuration:

- `timestamp` — when the event was processed
- `event_type` — the taxonomy event type name
- `severity` — resolved severity (0-10)
- `duration_ms` — request duration (middleware events)
- `event_category` — which category triggered delivery
- `app_name` — application identifier (required at construction; `audit.New()` returns `ErrAppNameRequired` if unset)
- `host` — hostname (required at construction; `audit.New()` returns `ErrHostRequired` if unset)
- `timezone` — timezone context (always populated; defaults to `time.Now().Location().String()` if `WithTimezone` is not provided)
- `pid` — process ID (always present)

This ensures every output receives a structurally valid, identifiable audit event.

## Performance

Sensitivity label exclusion operates inside the formatter's existing
field iteration loop. There is zero additional allocation or map copy
when sensitivity labels are configured — the `FormatOptions` are
pre-allocated per output at construction time.

## Further Reading

- [Progressive Example: Sensitivity Labels](../examples/11-sensitivity-labels/) — complete working example with PII and financial labels
- [Event Routing](event-routing.md) — per-output routing (complementary feature)
- [API Reference: SensitivityConfig](https://pkg.go.dev/github.com/axonops/audit#SensitivityConfig)
