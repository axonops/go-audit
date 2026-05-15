[&larr; Back to README](../README.md)

# Async Delivery and Pipeline Architecture

- [How Events Flow](#how-events-flow)
- [Why Async?](#why-async)
- [Buffering and Backpressure](#buffering-and-backpressure)
- [Two-Level Buffering](#two-level-buffering)
- [Delivery Guarantee](#delivery-guarantee)
- [Graceful Shutdown](#graceful-shutdown)
- [Thread Safety](#thread-safety)

## How Events Flow

```mermaid
flowchart LR
    A["AuditEvent()"] --> B[Validate fields]
    B --> C[Check category enabled]
    C --> D[Enqueue to channel]
    D --> E[Drain goroutine]
    E --> F[Set timestamp]
    F --> G["Serialize (JSON/CEF)"]
    G --> H[Fan-out to outputs]
    H --> I[Route filter]
    I --> J[Sensitivity filter]
    J --> K["Output.Write()"]
```

## Why Async?

Audit logging must not slow down the operations it audits, and
**output isolation is a security requirement**. If one output stalls
(a syslog server goes unreachable, a webhook endpoint is slow), it
must not prevent delivery to other outputs. Without async buffers, a
stalled output blocks the drain goroutine, silencing all auditing —
a cascade failure that is worse than losing events to a single
destination.

If writing to a syslog server takes 5ms, a synchronous audit call
would add 5ms to every request. The async pipeline decouples event
production from delivery:

- `AuditEvent()` validates and enqueues — sub-microsecond
- A single drain goroutine reads events from the channel **continuously** as they arrive — there is no periodic flush interval
- Your application continues immediately after the call returns

### Is Async Acceptable for Compliance?

Yes. Asynchronous audit delivery is standard practice across the
industry:

- **Linux Audit (auditd)** writes events to a kernel ring buffer and
  drains asynchronously to disk — the syscall does not block on I/O
- **Windows Event Log** uses an asynchronous ETW (Event Tracing for
  Windows) pipeline
- **Cloud platforms** (AWS CloudTrail, GCP Cloud Audit Logs, Azure
  Activity Log) all deliver events asynchronously with eventual
  consistency guarantees

The key is not synchronous delivery — it is **completeness monitoring**.
audit provides this through the [Metrics interface](metrics-monitoring.md):

- `RecordBufferDrop()` fires if an event is lost at the core queue
- `RecordSubmitted()` counts every event entering the pipeline
- `OutputMetrics.RecordDrop()` fires if an event is lost at a per-output buffer
- `RecordOutputError()` fires if a synchronous output fails to write

Wire these to your monitoring system and alert on any non-zero buffer
drops or output errors. This gives you the same assurance as
synchronous delivery: if an event is lost, you know about it.

The library is not a database — it is a pipeline component within
your application process. Synchronous audit logging would mean your
HTTP handler blocks on syslog TCP writes, which creates cascading
failures when the syslog server is slow or unreachable. Async delivery
with monitoring is both safer and more reliable in practice.

## Buffering and Backpressure

Events are held in a buffered channel. The drain goroutine reads from
this channel continuously — events are processed as fast as the
outputs can write them.

### Configuration

Buffer and drain settings are configured in the `auditor:` section of
your output YAML:

```yaml
auditor:
  queue_size: 50000          # default: 10,000, max: 1,000,000
  shutdown_timeout: "30s"       # default: "5s", max: "60s"
```

Or programmatically via functional options:

```go
auditor, err := audit.New(
    audit.WithQueueSize(50_000),
    audit.WithShutdownTimeout(30 * time.Second),
    audit.WithTaxonomy(tax),
    audit.WithOutputs(out),
)
```

When using `outputconfig.Load`, `result.Options` includes
config-equivalent options (`WithQueueSize`, `WithShutdownTimeout`, etc.)
from your YAML — pass them directly to `New`.

| Field | Default | Max | What It Does |
|-------|---------|-----|-------------|
| `QueueSize` | 10,000 | 1,000,000 | Capacity of the core intake queue. When full, `AuditEvent()` returns `ErrQueueFull` and the event is lost. |
| `ShutdownTimeout` | 5 seconds | 60 seconds | How long `Close()` waits for remaining events to flush before giving up. Events still in the buffer after this timeout are lost. |

**Note:** `ShutdownTimeout` only applies during shutdown (when you call
`Close()`). During normal operation, the drain goroutine processes
events continuously with no timeout.

### Sizing the Buffer

- **Low volume** (< 100 events/sec) — default 10,000 is more than enough
- **High volume** (1,000+ events/sec) — increase if you see buffer drops
- **Slow outputs** (high-latency webhooks) — larger buffer absorbs spikes

Monitor `RecordBufferDrop()` — if it fires, your buffer is too small
or your outputs are too slow.

## Two-Level Buffering

audit has a two-level buffering architecture. Understanding it is
essential for tuning performance and diagnosing event drops.

### Level 1: Core Auditor Buffer

Every `AuditEvent()` call validates the event and enqueues it into a
buffered Go channel. A single drain goroutine reads from this channel,
serialises each event, and delivers it to every configured output.

```
AuditEvent()
  → validate against taxonomy
  → enqueue to channel (capacity: WithQueueSize, default 10,000)
  → return immediately (sub-microsecond)

Drain goroutine (single, runs continuously)
  → dequeue entry
  → set timestamp
  → serialise (JSON or CEF, cached per format)
  → deliver to output 1, then output 2, then output 3, ...
  → return entry to sync.Pool for reuse
```

If the channel is full, `AuditEvent()` returns `ErrQueueFull` and the
event is lost. The `RecordBufferDrop()` metric fires on every drop.

### Level 2: Per-Output Buffer (All Outputs Except Stdout)

Every output except stdout has its own internal buffered channel and
a background goroutine. File and syslog outputs write one event at a
time from their `writeLoop` goroutine. Webhook and Loki outputs
accumulate events into batches before sending them as HTTP requests.

```
Drain goroutine                        Output goroutine
───────────────                        ────────────────
  delivers to any async output           reads from output channel
    → Write() / WriteWithMetadata()      → file/syslog: write to disk/TCP
    → copies event bytes                 → webhook/loki: accumulate batch
    → enqueues to output channel             flush when batch_size reached,
      (capacity: output buffer_size,         flush_interval elapsed, or
       default 10,000)                       shutdown
    → returns immediately                → HTTP POST to destination
                                         → retry on 429/5xx (webhook/loki)
```

If the output's channel is full (e.g., the destination is down and
retries are consuming time), new events are dropped. The
`OutputMetrics.RecordDrop()` method fires on every drop. A rate-limited
`slog.Warn` diagnostic fires at most once per 10 seconds. Drops in one
output's buffer do not affect other outputs.

### The Complete Pipeline

```
                    Level 1                              Level 2
                    ───────                              ───────
AuditEvent() ──► core queue  ──► drain goroutine ─┬──► Stdout.Write()                  [synchronous]
                 (queue_size)     (single)         ├──► File.Write() ──────────────────► writeLoop ──► disk
                                                   │    (buffer_size, default 10,000)
                                                   ├──► Syslog.WriteWithMetadata() ────► writeLoop ──► TCP/UDP
                                                   │    (buffer_size, default 10,000)
                                                   ├──► Webhook.Write() ───────────────► batchLoop ──► HTTP POST
                                                   │    (buffer_size, default 10,000)
                                                   └──► Loki.WriteWithMetadata() ──────► batchLoop ──► HTTP POST
                                                        (buffer_size, default 10,000)
```

Outputs that implement `MetadataWriter` (Loki, Syslog) receive
per-event metadata (event type, severity, category, timestamp)
alongside the serialised bytes. Loki uses this for stream labels;
Syslog uses it for RFC 5424 severity mapping.

### Key Implications

**Only stdout writes synchronously.** All other outputs (file, syslog,
webhook, Loki) have their own internal buffer and background goroutine.
A stalled file or syslog destination drops events into its own buffer
rather than blocking the drain goroutine. This means a dead syslog
server does not prevent file or webhook delivery.

**Per-output drops are isolated.** If Loki's buffer fills because
Loki is down, Loki drops events but the core queue and all other
outputs are unaffected.

**`queue_size` and `buffer_size` are different things.**
`auditor.queue_size` (or `WithQueueSize`) is the Level 1 core
intake queue. `buffer_size` on any output (file, syslog, webhook,
Loki) is that output's Level 2 channel. They are independent. Both
default to 10,000 but they serve different purposes.

**`batch_size` is not `buffer_size`.** `batch_size` controls how many
events are grouped into a single HTTP request (webhook and Loki only).
`buffer_size` controls how many events can queue up waiting to be
written or batched. With the defaults (`buffer_size: 10000`,
`batch_size: 100`), up to 100 batches of events can be queued before
drops begin.

### Memory Sizing

The core library uses a package-level `sync.Pool` shared across all
`Auditor` instances to reuse `auditEntry` structs, reducing GC pressure
on the hot path. Pool entries are returned after the drain goroutine
finishes processing each event. The channel holds pointers to
pool-allocated structs, not copies.

For Level 2 buffers (Loki, webhook), each entry is a byte slice copy
of the serialised event. Typical sizes:

| Event Complexity | Approximate Serialised Size |
|------------------|-----------------------------|
| Minimal (3 fields + framework) | ~200 bytes |
| Typical (8–10 fields + framework) | ~500 bytes |
| Large (20+ fields + framework) | ~1,200 bytes |

Memory per Level 2 buffer at default 10,000 capacity:

| Event Size | Buffer Memory |
|------------|---------------|
| 200 bytes | ~2 MB |
| 500 bytes | ~5 MB |
| 1,200 bytes | ~12 MB |

The Loki Level 2 buffer holds `lokiEntry` structs, not raw byte
slices. Each entry carries the serialised bytes plus an
`EventMetadata` value (event type, severity, category, timestamp) —
add approximately 80–120 bytes per entry for the metadata overhead.

With the core buffer + one Loki buffer + one webhook buffer, worst
case with large events: ~36 MB of buffered events. This is usually
negligible, but relevant when tuning buffer sizes for
memory-constrained environments.

### Tuning Guidance

| Symptom | Diagnosis | Fix |
|---------|-----------|-----|
| `ErrQueueFull` from `AuditEvent()` | Core queue (Level 1) full — drain goroutine can't keep up | Increase `auditor.queue_size` |
| `OutputMetrics.RecordDrop()` firing | Per-output buffer (Level 2) full — destination too slow or down | Increase output `buffer_size`, decrease `flush_interval`, check destination health |
| High event latency | Events queued too long before flushing | Decrease `flush_interval` or `batch_size` for faster delivery |
| Excessive memory | Large buffers with large events | Decrease `buffer_size` on outputs you can afford to drop from |

## Delivery Guarantee

**At-most-once within a process lifetime.**

An event is either delivered to all outputs or lost. Events can be
lost in two scenarios:

1. **Queue full** — `AuditEvent()` returns `ErrQueueFull`
2. **Shutdown timeout** — events still in the buffer when `Close()`'s
   drain timeout expires are dropped with a warning

Events are never duplicated at the pipeline level. (The webhook output
has its own at-least-once retry semantics for HTTP delivery — see
[Outputs](outputs.md).)

## Graceful Shutdown

`Auditor.Close()` MUST be called when the auditor is no longer needed:

1. Signals the drain goroutine to stop accepting new events
2. Flushes pending events from the buffer (up to `ShutdownTimeout`)
3. Closes all outputs in parallel
4. Returns any close errors

**Failing to call Close leaks the drain goroutine and loses all
buffered events.**

### Where to Call Close

In a typical Go HTTP server, use signal handling to ensure `Close()`
is called before the process exits:

```go
func main() {
    auditor, err := audit.New(opts...)
    if err != nil {
        log.Fatal(err)
    }

    srv := &http.Server{Addr: ":8080", Handler: router}

    // Start server in background.
    go func() {
        if err := srv.ListenAndServe(); err != http.ErrServerClosed {
            log.Printf("http: %v", err)
        }
    }()

    // Wait for SIGINT or SIGTERM.
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    // 1. Stop accepting new HTTP requests.
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    srv.Shutdown(ctx)

    // 2. Close the auditor — flushes all pending audit events.
    if err := auditor.Close(); err != nil {
        log.Printf("audit close: %v", err)
    }

    log.Println("shutdown complete")
}
```

**Key ordering:** Stop the HTTP server first (so no new audit events
are generated), then close the auditor (so all pending events flush).

For simpler applications without an HTTP server, `defer` works:

```go
func main() {
    auditor, err := audit.New(opts...)
    if err != nil {
        log.Fatal(err)
    }
    defer func() {
        if err := auditor.Close(); err != nil {
            log.Printf("audit close: %v", err)
        }
    }()

    // ... your application logic ...
}
```

See [Progressive Example: Capstone](../examples/20-capstone/) for a
complete working example with signal handling.

## Thread Safety

- `AuditEvent()` is safe for concurrent use from any number of goroutines
- Category enable/disable uses lock-free reads on the hot path
- The single drain goroutine means outputs do not need to be thread-safe
- `Close()` is idempotent via `sync.Once`

## Further Reading

- [Progressive Example: Buffering](../examples/14-buffering/) — runnable demo of both levels of backpressure
- [Metrics and Monitoring](metrics-monitoring.md) — tracking buffer drops and output failures
- [Outputs](outputs.md) — output types and fan-out architecture
- [Architecture](../ARCHITECTURE.md) — pipeline implementation details
- [Deployment Guide — Capacity Planning](deployment.md#capacity-planning) — operator-facing tier table for `queue_size` / `buffer_size` / `shutdown_timeout` against event-rate
