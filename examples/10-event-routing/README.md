[← Back to examples](../README.md)

> **Previous:** [09 — Multi-Output](../09-multi-output/) |
> **Next:** [11 — Sensitivity Labels](../11-sensitivity-labels/)
# Example 10: Event Routing

Route different event categories to different outputs: security events
to one file, write events to another, and everything to the console.

## What You'll Learn

- Setting per-category severity levels in the taxonomy
- Adding per-output routing rules in `outputs.yaml`
- How `include_categories` and `exclude_categories` work
- Severity-based routing with `min_severity` and `max_severity`
- What happens to events that don't match any route

## Prerequisites

- Go 1.26+
- Completed: [Multi-Output](../09-multi-output/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Three categories: write, read, security (with severity) |
| `outputs.yaml` | Four outputs with different routing rules |
| `audit_generated.go` | Generated constants (committed) |
| `main.go` | Emits one event per category, shows filtered output |

## Key Concepts

### Category Severity in the Taxonomy

This example's `taxonomy.yaml` uses a new category format — notice the
`security` category has a `severity: 8`:

```yaml
categories:
  write:
    - user_create        # list format (severity defaults to 5)
  read:
    - user_read          # list format
  security:
    severity: 8          # struct format — all events inherit severity 8
    events:
      - auth_failure
```

audit supports two ways to define categories:

- **List format** — just the event names. Events get the default
  severity of 5.
- **Struct format** — an object with `severity` and `events` keys.
  Every event in this category inherits the category's severity unless
  the event defines its own.

Both formats can be mixed in the same taxonomy file. The
[Capstone](../20-capstone/) example shows every category using the struct
format with different severity levels.

### Per-Event Severity Override

Individual events can override their category's severity:

```yaml
events:
  auth_failure:
    severity: 9     # overrides category severity of 8
    fields:
      outcome: {required: true}
```

Resolution chain: event severity (if set) -> category severity -> 5.
The [Capstone](../20-capstone/) example uses this: `auth_failure` is
severity 9 while other security events are severity 8.

### Routes in YAML

Each output can have a `route:` block that controls which events it
receives:

```yaml
version: 1
outputs:
  console:
    type: stdout
    # No route — receives ALL events.

  security_log:
    type: file
    file:
      path: "./security.log"
    route:
      include_categories:
        security: {}

  writes_log:
    type: file
    file:
      path: "./writes.log"
    route:
      include_categories:
        write: {}
```

- **No route** = receives everything (the console output above)
- **`include_categories`** = allow-list — only events in these categories
- **`exclude_categories`** = deny-list — everything except these categories

You can also filter by individual event types with `include_event_types`
and `exclude_event_types`.

### Route Validation

Routes are validated against your taxonomy when the config is loaded. If
you reference a category that doesn't exist in your taxonomy,
`outputconfig.Load` returns an error immediately — no silent
misconfiguration.

### What Happens to Unmatched Events

An event that doesn't match any routed output is simply not delivered to
that output. In this example, the `user_read` event (category `read`)
doesn't match either file's route, so it only appears on stdout.

Events are filtered before serialization — no wasted work formatting
events that won't be delivered.

### Severity-Based Routing

Each output's route can filter by severity level (0-10). This
example's `outputs.yaml` includes a `critical_alerts` output with
`min_severity: 7`. Below are the three routing modes you can use:

**Category only** — filter by category, all severity levels:
```yaml
  security_log:
    type: file
    file:
      path: "./security.log"
    route:
      include_categories: {security: {}}
```

**Category with per-category severity** (#193) — each included
category can carry its own severity bound. The bound goes **inside**
the category mapping value, not at the route level. A category
match never falls back to route-level severity — to constrain a
category by severity, place the bound inside its mapping:
```yaml
  security_critical:
    type: file
    file:
      path: "./security-critical.log"
    route:
      include_categories:
        security:
          min_severity: 7   # only security events at severity >= 7
```

**Severity only** — filter by severity regardless of category. This
is the PagerDuty use case — route all high-severity events to an
alerting webhook:
```yaml
  pagerduty:
    type: webhook
    webhook:
      url: "https://alerts.example.com/pagerduty"
    route:
      min_severity: 9
```

Each output has exactly one route. `min_severity` and `max_severity`
accept values 0-10.

### Multi-Category Events

An event can belong to multiple categories. For example, an
`admin_delete` event might belong to both `write` and `admin`:

```yaml
categories:
  write:
    - admin_delete
  admin:
    severity: 7
    events:
      - admin_delete
```

When a multi-category event is emitted, the auditor processes it once
per enabled category. If `write` routes to a file output and `admin`
routes to a webhook, the event is delivered to both — each with the
severity from its respective category. This means the same event can
appear multiple times in a fan-out output that matches multiple
categories.

## Run It

```bash
go run .
```

## Expected Output

All three events appear on stdout (all events). Each file contains only
the events matching its route:

```
INFO audit: auditor created queue_size=10000 shutdown_timeout=5s validation_mode=strict outputs=4 synchronous=false
INFO audit: shutdown started
... (stdout shows all three events)
INFO audit: shutdown complete duration=...

--- security.log ---
{"timestamp":"...","event_type":"auth_failure","severity":8,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"unknown","outcome":"failure","event_category":"security"}

--- writes.log ---
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"alice","outcome":"success","event_category":"write"}

--- critical.log ---
{"timestamp":"...","event_type":"auth_failure","severity":8,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"unknown","outcome":"failure","event_category":"security"}
```

The `user_read` event doesn't appear in any file — no route includes
the `read` category, and its severity (5) is below the critical
threshold (7). The `auth_failure` event appears in both `security.log`
(category route) and `critical.log` (severity route) — it matches both
independently.

## Further Reading

- [Event Routing](../../docs/event-routing.md) — full routing reference with all filter options
- [Output Configuration YAML](../../docs/output-configuration.md) — route syntax in YAML

