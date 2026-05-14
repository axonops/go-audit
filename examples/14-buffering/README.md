[← Back to examples](../README.md)

> **Previous:** [13 — TLS Policy](../13-tls-policy/) |
> **Next:** [15 — HTTP Middleware](../15-middleware/)
# Example 14: Buffering and Backpressure

Demonstrates the two-level buffering architecture that sits between
your `AuditEvent()` call and the final output destinations. Understanding
this architecture is essential for tuning performance and diagnosing
event drops in production.

## What You'll Learn

- Why audit has two levels of buffering and how they interact
- What `ErrQueueFull` means and when it fires (Level 1)
- What `OutputMetrics.RecordDrop()` means (Level 2)
- The difference between `queue_size`, `buffer_size`, and `batch_size`
- How per-output async buffers provide isolation — this is a security
  requirement: a stalled output must not silence all auditing
- How to tune buffer sizes for your workload

## Prerequisites

- Completed: [Multi-Output](../09-multi-output/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Simple 2-event taxonomy |
| `outputs.yaml` | Core buffer (size 5) + file output + webhook output (unreachable endpoint) |
| `audit_generated.go` | Generated typed builders |
| `main.go` | Emits events in a burst to trigger both levels of backpressure |

## Key Concepts

### The Two-Level Pipeline

```
                    Level 1                              Level 2
                    ───────                              ───────
AuditEvent() ──► core queue  ──► drain goroutine ─┬──► Stdout.Write()                  [synchronous]
                 (queue_size)     (single)         ├──► File.Write() ──────────────────► writeLoop ──► disk
                                                   │    (buffer_size)
                                                   └──► Webhook.Write() ───────────────► batchLoop ──► HTTP POST
                                                        (buffer_size)
```

**Level 1** is the core intake queue — a Go channel between
`AuditEvent()` and the drain goroutine. When full, `AuditEvent()`
returns `ErrQueueFull` and the event is lost.

**Level 2** exists in all outputs except stdout. Every non-stdout
output has its own internal channel and a background goroutine.
File and syslog write one event at a time; webhook and Loki
accumulate events into batches before sending HTTP requests.
When any output's buffer fills, events are dropped with metrics.

Only stdout writes synchronously from the drain goroutine.

### `queue_size` vs `buffer_size` vs `batch_size`

Three different configs that mean different things:

| Config | Where | Default | What It Controls |
|--------|-------|---------|------------------|
| `auditor.queue_size` | YAML `logger:` section | 10,000 | Level 1 core queue capacity |
| output `buffer_size` | Per output (file, syslog, webhook, Loki) | 10,000 | Level 2 per-output channel capacity |
| output `batch_size` | Per webhook/Loki output | 100 | Events grouped per HTTP POST |

`batch_size` is **not** `buffer_size`. With defaults (`buffer_size:
10000`, `batch_size: 100`), up to 100 batches of events can queue
before Level 2 drops begin.

### Why a Slow Synchronous Output Blocks Everything

All non-stdout outputs have their own internal async buffer. The
drain goroutine enqueues events into each output's buffer and moves
on immediately. A stalled destination (unreachable webhook, slow
syslog) drops events into its own buffer without affecting other
outputs.

### What This Example Demonstrates

1. **Core queue fills** — `queue_size: 5` in `outputs.yaml` means
   only 5 events fit in the channel. Emitting 20 events in a tight
   loop causes 14+ `ErrQueueFull` returns.

2. **Webhook drops** — the webhook points at `http://localhost:19999`
   where nothing is listening. Delivery fails, retries exhaust, and
   the batch is dropped. The `slog.Warn` and `slog.Error` diagnostics
   on stderr show this happening.

3. **File output is unaffected** — the file output has its own async
   buffer and succeeds for every event that made it through the core
   queue. Webhook failures do not affect file delivery.

### Output Configuration

```yaml
# Level 1 — core queue
auditor:
  queue_size: 5            # Tiny queue to trigger ErrQueueFull
  shutdown_timeout: "2s"

outputs:
  # Async file output — has its own internal buffer
  audit_file:
    type: file
    file:
      path: "./audit-buffering-demo.log"

  # Async webhook output — has its own buffer and batch goroutine
  webhook_demo:
    type: webhook
    webhook:
      url: "http://localhost:19999/audit"     # Nothing listening
      allow_insecure_http: true
      allow_private_ranges: true
      buffer_size: 10        # Level 2 buffer
      batch_size: 5          # Events per HTTP POST
      flush_interval: "1s"
      timeout: "1s"
      max_retries: 1
```

## Run It

```bash
go run .
```

## Expected Output

```
INFO audit: auditor created queue_size=5 shutdown_timeout=2s validation_mode=strict outputs=2 synchronous=false
--- Level 1: Core Queue (queue_size: 5) ---
Emitting 20 events in a tight loop...
WARN audit: queue full, events dropped dropped=1 queue_size=5
  Delivered: 6, Dropped (ErrQueueFull): 14
  → Core queue was full. In production, increase auditor.queue_size.

--- Level 2: Webhook Buffer (buffer_size: 10) ---
The webhook points at an unreachable endpoint.
Watch stderr for drop warnings from the webhook output.
The file output (async, separate buffer) is unaffected.
WARN audit: webhook retryable error attempt=1 max_retries=1 error="..."
ERROR audit: webhook retries exhausted, dropping batch batch_size=5 max_retries=1
# ... additional webhook errors for remaining events (partial batch flush at shutdown)

--- Buffering Architecture Summary ---
  (architecture diagram and tuning guidance)

INFO audit: shutdown started
INFO audit: shutdown complete duration=...
```

The `INFO` and `WARN` lines are lifecycle diagnostics on stderr.
The exact number of delivered vs dropped events may vary by machine
speed — the key point is that `ErrQueueFull` fires when the core
queue is full, and the webhook drops events independently without
affecting the file output.

## Tuning for Production

| Symptom | Fix |
|---------|-----|
| `ErrQueueFull` from `AuditEvent()` | Increase `auditor.queue_size` (default 10,000, max 1,000,000) |
| `OutputMetrics.RecordDrop()` | Increase output `buffer_size`, decrease `flush_interval` |
| High event latency | Decrease `flush_interval` or `batch_size` |
| Excessive memory | Decrease `buffer_size` (each 10,000 events ≈ 5 MB with typical events) |

## Further Reading

- [Two-Level Buffering](../../docs/async-delivery.md#two-level-buffering) — complete architecture reference
- [Output Types](../../docs/outputs.md#buffering-and-delivery-model) — sync vs async comparison table
- [Webhook Output](../../docs/webhook-output.md#buffering-architecture) — webhook buffering details
- [Loki Output](../../docs/loki-output.md#buffering-architecture) — Loki buffering details
