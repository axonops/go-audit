[← Back to examples](../README.md)

> **Previous:** [02 — Code Generation](../02-code-generation/) |
> **Next:** [04 — Formatters](../04-formatters/)
# Example 03: File Output

Write audit events to a log file with automatic rotation, size limits,
and restricted file permissions.

## What You'll Learn

- Configuring a file output in `outputs.yaml`
- Enabling output types with blank imports
- File rotation, backup retention, and permissions
- Why `Close()` is critical for file output

## Prerequisites

- Go 1.26+
- Completed: [Basic](../01-basic/), [Code Generation](../02-code-generation/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Event definitions (embedded in binary) |
| `outputs.yaml` | File output configuration |
| `audit_generated.go` | Generated constants (committed) |
| `main.go` | Loads config, emits events, reads file back |

## Key Concepts

### File Output in YAML

The `outputs.yaml` configures a single file output with rotation:

```yaml
version: 1
outputs:
  audit_log:
    type: file
    file:
      path: "./audit.log"
      max_size_mb: 10
      max_backups: 3
```

The `type: file` tells the library to use the file output module. The
type-specific settings are nested under a key matching the type name
(`file:`).

### Available File Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `path` | (required) | File path. Created if it doesn't exist. |
| `max_size_mb` | 100 | Rotate when the file exceeds this size. |
| `max_backups` | 5 | Number of rotated files to keep. |
| `max_age_days` | 30 | Delete rotated files older than this. |
| `group_readable` | `false` | When `true`, mode is `0o640` (owner + group read) for SIEM forwarders running in the file's group. Default `false` is `0o600` (owner only). |
| `compress` | `true` | Gzip rotated files. |
| `fsync_each_batch` | `false` | When `true`, each batched write is `writev(2)` + `fsync(2)`. See [Durability vs Throughput](#durability-vs-throughput) below. |

### Durability vs Throughput

By default the file output writes events to the OS page cache and
lets the kernel flush to disk on its own schedule. This is fast
but creates a brief window where a crash (kernel panic, power
loss, container OOM-kill of the writer's host) can lose the most
recent batch. For compliance use cases that require each event be
on stable storage before the next acknowledgement, set:

```yaml
file:
  path: "./audit.log"
  fsync_each_batch: true   # see #678
```

With `fsync_each_batch: true`, every flushed batch becomes
`writev(2) + fsync(2)`. The drain goroutine's throughput is then
bounded by the disk's fsync latency:

- Rotational disks: ~5–50 ms per batch.
- Local SSD: ~0.1–2 ms per batch.
- Network filesystems (NFS, EFS): highly variable; benchmark before
  enabling.

The sustained event rate is approximately
`batch_size / (writev_latency + fsync_latency)`. For a 256-event
batch on an SSD this is still tens of thousands of events per
second — well above most audit workloads — but the latency floor
matters for back-pressure tuning. See `BENCHMARKS.md` for figures
on your platform.

**Partial guarantee.** `fsync_each_batch: true` fsyncs the audit
log file, but does NOT fsync the parent directory. After a crash
during log rotation the post-rotation file's directory entry may
not yet be on disk. For directory-level durability, mount the
audit-log directory with `dirsync` (Linux), or accept that the
rotated tail may not survive a crash that hits at exactly the
rotation moment.

### Enabling the File Output Type

The file output lives in its own Go module. The easiest way to
register it (along with every other built-in output) is to blank-
import the convenience package:

```go
import (
    "github.com/axonops/audit/outputconfig"
    _ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
)
```

If you prefer to register only the outputs you use (smaller binary
for constrained deployments), import the individual sub-module
instead:

```go
import _ "github.com/axonops/audit/file"
```

If `type: file` appears in YAML without either import,
`outputconfig.Load` returns an error like:
`output "audit_log": unknown output type "file" (registered: []); add import _ "github.com/axonops/audit/outputs" for all built-in types (or import _ "github.com/axonops/audit/file" for only this one)`

### Close Flushes to Disk

For file outputs, `Close()` is especially important. The auditor buffers
events in memory and writes them asynchronously. If you exit without
`Close()`, events still in the buffer never reach the file.

## Run It

```bash
go run .
```

## Expected Output

```
INFO audit: auditor created queue_size=10000 shutdown_timeout=5s validation_mode=strict outputs=1 synchronous=false
INFO audit: shutdown started
INFO audit: shutdown complete duration=...
--- Contents of audit.log ---
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"alice","outcome":"success","event_category":"write"}
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"bob","outcome":"success","event_category":"write"}
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"carol","outcome":"success","event_category":"write"}
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"dave","outcome":"success","event_category":"write"}
{"timestamp":"...","event_type":"user_create","severity":5,"app_name":"example","host":"localhost","timezone":"Local","pid":...,"actor_id":"eve","outcome":"success","event_category":"write"}
```

Five JSON events written to `audit.log`, each with the `event_category`
field from the taxonomy. The file is cleaned up at the end of the example.

## Further Reading

- [Outputs](../../docs/outputs.md) — output types and fan-out architecture
- [Output Configuration YAML](../../docs/output-configuration.md) — full YAML reference

