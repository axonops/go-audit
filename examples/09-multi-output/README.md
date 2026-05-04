[← Back to examples](../README.md)

> **Previous:** [08 — Webhook Output](../08-webhook-output/) |
> **Next:** [10 — Event Routing](../10-event-routing/)

# Example 09: Multi-Output Fan-Out

Send every audit event to multiple destinations simultaneously — stdout
and a log file, both defined in `outputs.yaml`.

## What You'll Learn

- Defining multiple outputs in one YAML config
- How fan-out delivery works
- Temporarily disabling an output with `enabled: false`
- What happens when one output fails

## Prerequisites

- Go 1.26+
- Completed: [File Output](../03-file-output/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Event definitions (embedded) |
| `outputs.yaml` | Three outputs: stdout + file + disabled file |
| `audit_generated.go` | Generated constants (committed) |
| `main.go` | Loads config, emits events, shows both outputs received them |

## Key Concepts

### Multiple Outputs in YAML

```yaml
version: 1
outputs:
  console:
    type: stdout

  audit_log:
    type: file
    file:
      path: "./audit.log"

  debug_file:
    enabled: false
    type: file
    file:
      path: "./debug.log"
```

Every output listed under `outputs:` receives every event. One
`AuditEvent()` call fans out to all of them. The output names (`console`,
`audit_log`) appear in metrics and error messages.

### Disabling an Output

Set `enabled: false` on any output to skip it at load time. The output
is not created, receives no events, and consumes no resources. This is
useful for:

- **Temporarily silencing a noisy output** during debugging
- **Environment-specific config** — leave a Loki output in the YAML but
  disable it in environments where Loki isn't available
- **Staged rollouts** — add a new output disabled, deploy, then flip
  `enabled: true` in the next deployment

Remove the `enabled: false` line (or set it to `true`) to re-enable.
The output's full config is preserved so you don't need to rewrite it.

### How Fan-Out Works

The auditor serializes each event once, then writes the same bytes to
each output in the order they appear in the YAML. If one output's write
fails, the error is recorded in metrics but the other outputs still
receive the event.

### When to Add Routing

Without routing rules, every output gets every event. The next example
([Event Routing](../10-event-routing/)) shows how to send different event
categories to different outputs.

## Run It

```bash
go run .
```

## Expected Output

Three JSON events appear on stdout, followed by the same three events
read back from `audit.log`:

```
INFO audit: auditor created queue_size=10000 shutdown_timeout=5s validation_mode=strict outputs=2 synchronous=false
INFO audit: shutdown started
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"alice","outcome":"success","event_category":"write"}
{"timestamp":"...","event_type":"auth_failure","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"unknown","outcome":"failure","event_category":"security"}
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"bob","outcome":"success","event_category":"write"}
INFO audit: shutdown complete duration=...

--- Contents of audit.log ---
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"alice","outcome":"success","event_category":"write"}
{"timestamp":"...","event_type":"auth_failure","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"unknown","outcome":"failure","event_category":"security"}
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"bob","outcome":"success","event_category":"write"}
```

Both outputs received identical events — that's fan-out. Note `outputs=2`
in the auditor-created message confirms both outputs are registered.

## Further Reading

- [Outputs](../../docs/outputs.md) — fan-out architecture and delivery guarantees
- [Async Delivery](../../docs/async-delivery.md) — how events flow through the pipeline

