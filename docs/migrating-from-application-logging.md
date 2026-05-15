# Migrating from Application Logging

This guide helps teams add audit logging alongside existing
application logging. **You need both** — audit logging does not
replace `slog`, `zap`, `zerolog`, or `logrus`. Application logs
record technical details for debugging; audit logs record **who did
what, when, and to which resource** for compliance, forensics, and
accountability.

The runnable companion to this guide is
[`examples/18-migration/`](../examples/18-migration/), which shows
the coexistence pattern in a small HTTP service.

## Audit logging vs application logging

| | Application logging | Audit logging |
|---|---|---|
| **Purpose** | Debugging, observability | Compliance, forensics, accountability |
| **Audience** | Developers, SREs | Security teams, auditors, legal |
| **Content** | Technical details (errors, stack traces, timing) | Who did what, when, to which resource, and why |
| **Guarantees** | Best-effort | Schema-enforced, validated against a taxonomy |
| **Retention** | Days to weeks | Months to years (regulatory requirements) |
| **Destinations** | Log aggregator (OpenSearch, Datadog, Loki) | SIEM (Splunk, ArcSight, QRadar), compliance archives |

## When to audit vs when to log

| Use audit | Use the application logger |
|---|---|
| User authentication success/failure | HTTP request tracing |
| Data creation, modification, deletion | Database query timing |
| Permission and role changes | Cache hit/miss ratios |
| Configuration changes | Error stack traces |
| Access to sensitive data (PII, financial) | Debug information |

A single request typically produces one or two audit events
(start, outcome) and several application log lines. They do not
duplicate each other.

## Transformation tables

The audit library replaces an application logger's free-form
key-value pairs with **typed, validated builders generated from
your taxonomy**. The "before" column shows the alternative-logger
idiom; the "after" column shows the audit equivalent. Apply these
mappings when adding audit alongside an existing logger — you do
not remove the application logger; you keep both.

> 📌 **Required fields are constructor parameters, not setters.**
> A field declared `required: true` in your taxonomy is generated
> as a positional argument on the builder constructor (e.g.,
> `NewUserCreateEvent(actorID, outcome)`). Optional fields and
> reserved standard fields become `.SetXxx(...)` methods on the
> builder. Whether a given field is `actor_id`, `outcome`,
> `source_ip`, or `reason` therefore depends on **your** taxonomy —
> the tables below assume `actor_id` and `outcome` are required
> (the most common shape) and treat the rest as optional setters.
> See [`docs/code-generation.md`](code-generation.md) for the full
> required-vs-optional contract.

### logrus → audit

[`logrus`](https://github.com/sirupsen/logrus) is the canonical
structured logger many older Go services use.

| Before (logrus) | After (audit) |
|---|---|
| `log.WithFields(log.Fields{"actor": id}).Info("user created")` | `auditor.AuditEvent(NewUserCreateEvent(id, "success"))` |
| `log.WithError(err).Warn("auth failed")` | `auditor.AuditEvent(NewAuthFailureEvent(user, "failure").SetReason(err.Error()))` |
| `log.WithFields(log.Fields{...}).Error("delete denied")` | `auditor.AuditEvent(NewUserDeleteEvent(actor, "denied").SetReason("not authorized"))` |
| `log.SetFormatter(&log.JSONFormatter{})` | configured per-output in `outputs.yaml` (`formatter: { type: json }`) |
| `log.SetOutput(file)` | configured per-output in `outputs.yaml` (`type: file`) |

Free-form fields such as `request_id`, `session_id`, `source_ip`
become typed setters: `.SetRequestID(string)`, `.SetSessionID(string)`,
`.SetSourceIP(string)`. Misspellings are compile errors.

### zap → audit

[`zap`](https://github.com/uber-go/zap) is Uber's high-performance
structured logger. Its strongly-typed field constructors map
directly onto the audit library's typed setters.

| Before (zap) | After (audit) |
|---|---|
| `logger.Info("user created", zap.String("actor", id))` | `auditor.AuditEvent(NewUserCreateEvent(id, "success"))` (`actor` is the required constructor arg) |
| `zap.String("target_id", t)` | `.SetTargetID(t)` on the generated builder |
| `zap.Int("port", 22)` | `.SetSourcePort(22)` |
| `zap.Time("started_at", t)` | `.SetStartTime(t)` |
| `logger.With(zap.String("request_id", rid))` | `.SetRequestID(rid)` per-event |
| `logger.Sugar().Infow("login", "user", u, "outcome", "fail")` | `auditor.AuditEvent(NewAuthFailureEvent(u, "failure"))` |

The `zap.Field` constructors and the audit setters share the same
shape: both are typed, both fail at compile time on type
mismatches, and both avoid the runtime allocation of free-form
key-value pairs.

### zerolog → audit

[`zerolog`](https://github.com/rs/zerolog) emphasises a chained
builder API. The audit library's generated builders use the same
fluent style.

| Before (zerolog) | After (audit) |
|---|---|
| `log.Info().Str("actor", id).Msg("user created")` | `auditor.AuditEvent(NewUserCreateEvent(id, "success"))` |
| `.Str("source_ip", ip)` | `.SetSourceIP(ip)` |
| `.Int("port", 443)` | `.SetDestPort(443)` |
| `.Time("at", t)` | `.SetStartTime(t)` |
| `log.Warn().Err(err).Msg("auth failed")` | `auditor.AuditEvent(NewAuthFailureEvent(user, "failure").SetReason(err.Error()))` |
| `log.Output(zerolog.ConsoleWriter{...})` | configured per-output in `outputs.yaml` |

The chaining `.Set...` calls in the audit builder mirror zerolog's
`.Str/.Int/.Time` calls; only the `.Msg(...)` terminator becomes
`auditor.AuditEvent(...)`.

### slog → audit

`log/slog` is the standard library's structured logger
(Go 1.21+). It is the most likely application logger to live
alongside audit in new code.

| Before (slog) | After (audit) |
|---|---|
| `slog.Info("user created", "actor", id)` | `auditor.AuditEvent(NewUserCreateEvent(id, "success"))` |
| `slog.Info("user updated", "user_id", actorID, "target", targetID)` | `auditor.AuditEvent(NewUserUpdateEvent(actorID, "success").SetTargetID(targetID))` |
| `slog.With("request_id", rid).Info("processed")` | `.SetRequestID(rid)` on the audit event |
| `slog.Error("auth failed", "user", u, "reason", "invalid creds")` | `auditor.AuditEvent(NewAuthFailureEvent(u, "failure").SetReason("invalid creds"))` |
| `slog.NewJSONHandler(os.Stdout, ...)` | configured per-output in `outputs.yaml` (`type: stdout` + `formatter: { type: json }`, the default) |

The audit library uses `slog` internally for its **own diagnostic
messages** (startup, shutdown, buffer-full warnings). See
[Redirecting audit diagnostics](#redirecting-audit-diagnostics)
below.

#### slog `NewEventKV` path

If you prefer a key-value style closer to `slog.Info(...)`, the
audit library exposes
[`audit.MustNewEventKV`](https://pkg.go.dev/github.com/axonops/audit#MustNewEventKV)
as an untyped fallback:

```go
auditor.AuditEvent(audit.MustNewEventKV("user_create",
    "outcome", "success",
    "actor_id", id,
))
```

Field validation happens at runtime against the taxonomy. Prefer
the generated typed builders (`NewUserCreateEvent(...)`) for
production code — typos and missing required fields become compile
errors instead of runtime errors.

## Coexistence pattern: an HTTP handler

The runnable HTTP example at
[`examples/18-migration/`](../examples/18-migration/) demonstrates
both loggers in the same handler. Sketch:

```go
type server struct {
    appLog  *slog.Logger
    auditor *audit.Auditor
}

func (s *server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
    start := time.Now()
    s.appLog.Info("create user request received",
        "method", r.Method, "path", r.URL.Path,
    )

    var body struct{ Name string `json:"name"` }
    if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
        s.appLog.Warn("decode request body", "error", err) // technical detail
        http.Error(w, "bad request", http.StatusBadRequest)
        return
    }

    actorID := r.Header.Get("X-Actor")
    // Audit event — schema-validated, who did what:
    if err := s.auditor.AuditEvent(
        NewUserCreateEvent(actorID, "success").
            SetTargetID(body.Name).
            SetSourceIP(r.RemoteAddr),
    ); err != nil {
        s.appLog.Error("audit emission failed", "error", err)
    }

    s.appLog.Info("create user complete",
        "duration_ms", time.Since(start).Milliseconds(),
    )
    w.WriteHeader(http.StatusCreated)
}
```

Notice the **non-overlap**:

- App log answers operational questions: was the service up, did
  the decoder fail, how long did the handler take.
- Audit event answers compliance questions: who created which
  user, from which source IP, at which time.

If audit emission fails, that itself is recorded on the application
log — SREs need to know about it. The audit event is **never**
emitted from inside the application logger; the two channels
remain independent.

## Redirecting audit diagnostics

The audit library uses `log/slog` for its own diagnostic messages
(auditor startup, shutdown, drain-loop errors, buffer-full
warnings). By default these go to `slog.Default()`. To send them
somewhere else — for example, a separate handler at a higher
level — pass `WithDiagnosticLogger` through `outputconfig.New`'s
variadic `opts` parameter:

```go
auditDiag := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
    Level: slog.LevelWarn, // only warnings and errors
}))

auditor, err := outputconfig.New(
    context.Background(),
    taxonomyYAML,
    "outputs.yaml",
    audit.WithDiagnosticLogger(auditDiag),
)
```

Diagnostic messages are **not** audit events — they describe the
auditor's own health, not actions in your application. A
production deployment typically routes them to the application log
aggregator, not the SIEM.

## See also

- [`examples/18-migration/`](../examples/18-migration/) — runnable HTTP service showing the coexistence pattern
- [`examples/15-middleware/`](../examples/15-middleware/) — HTTP middleware that auto-captures request fields
- [`docs/json-format.md`](json-format.md) — wire format for audit events on the application log channel
- [`docs/output-configuration.md`](output-configuration.md) — destinations and formatters
- [`docs/testing.md`](testing.md) — `audittest` package for unit-testing audit emission alongside HTTP handlers
