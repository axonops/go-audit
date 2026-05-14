[← Back to examples](../README.md)

> **Previous:** [17 — Testing](../17-testing/) |
> **Next:** [19 — Prometheus Reference](../19-prometheus-reference/)

---

# Example 18: Migrating from Application Logging

This example demonstrates the **coexistence pattern** between an
application logger (`log/slog`) and the audit library. It is the
runnable companion to
[`docs/migrating-from-application-logging.md`](../../docs/migrating-from-application-logging.md).

## What it shows

A small HTTP service with two handlers (`POST /users` and
`POST /login`) where every request:

1. Records technical detail to `slog` — request received, decode
   errors, timing, outcome.
2. Records compliance events through `audit` — `user_create`,
   `auth_success`, `auth_failure` — validated against
   [`taxonomy.yaml`](taxonomy.yaml).

The two loggers run independently. `slog` writes to stderr;
`audit` writes to stdout via [`outputs.yaml`](outputs.yaml).

## Running

```bash
go generate ./...   # regenerate audit_generated.go from taxonomy.yaml
go run .
```

In another shell:

```bash
# Successful user creation — emits user_create audit event.
curl -H 'X-Actor: alice' -X POST http://localhost:8080/users \
  -d '{"name":"new-user"}'

# Failed login — emits auth_failure audit event + an slog warning.
curl -u alice:wrong-password -X POST http://localhost:8080/login

# Successful login — emits auth_success audit event.
curl -u alice:correct-password -X POST http://localhost:8080/login
```

## Why both layers

| Question | App log (slog) | Audit (audit) |
|---|---|---|
| "Was the service up at 12:00?" | ✓ | — |
| "Did request decoding fail?" | ✓ | — |
| "How long did the handler take?" | ✓ | — |
| "Who created user `new-user` on 2026-04-15?" | — | ✓ |
| "Who attempted to log in as `alice` and failed?" | — | ✓ |
| "What changes did `bob` make to user records this quarter?" | — | ✓ |

The app log answers SRE / on-call questions. Audit events answer
compliance / forensic questions. Either alone is incomplete.

## See also

- [`docs/migrating-from-application-logging.md`](../../docs/migrating-from-application-logging.md) — full guide with logrus / zap / zerolog / slog transformation tables
- [Example 06 — HTTP Middleware](../15-middleware/) — middleware-based auditing for full request lifecycle
- [Example 17 — Capstone](../20-capstone/) — production-grade pattern with four outputs, HMAC, and Loki dashboards
