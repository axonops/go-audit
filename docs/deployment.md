# Deployment Guide

This guide answers the operator-side questions the rest of the docs
don't: where `outputs.yaml` lives, how to inject secrets without
shipping them in source, what the systemd unit looks like, what the
Kubernetes manifest set looks like, how to size queues for your
event rate, and how to deal with the file output's parent-directory
requirement.

It is intentionally narrow — production deployment patterns, not
library behaviour. For library behaviour, see the per-output docs
([file](file-output.md), [syslog](syslog-output.md),
[webhook](webhook-output.md), [loki](loki-output.md)) and
[output-configuration.md](output-configuration.md).

- [Filesystem Conventions](#filesystem-conventions)
- [Secret Injection](#secret-injection)
- [systemd Unit](#systemd-unit)
- [Kubernetes Manifests](#kubernetes-manifests)
- [Docker Compose](#docker-compose)
- [Container Hardening](#container-hardening)
- [File Output Parent-Directory Behaviour](#file-output-parent-directory-behaviour)
- [Capacity Planning](#capacity-planning)
- [Pre-Deploy Validation](#pre-deploy-validation)

## Filesystem Conventions

The library imposes no path on `outputs.yaml`; the operator picks the
location and passes it via the application's startup. The conventions
below match other Linux services and minimise surprise during
audits.

| Path | Permissions | Owner | Purpose |
|---|---|---|---|
| `/etc/<app>/outputs.yaml` | `0644` | `root:root` | The output configuration. World-readable; readable by the service UID. |
| `/etc/<app>/secrets/` | `0700` | `audit:audit` | Directory for secret material loaded via `ref+file://`. Never world-readable. |
| `/etc/<app>/secrets/hmac-salt` | `0400` | `audit:audit` | Whole-file secret. The library expects the trailing newline trimmed. |
| `/var/log/<app>/` | `0750` | `audit:audit` | File output destination. NOT a symlink (see [parent-directory behaviour](#file-output-parent-directory-behaviour)). |
| `/etc/<app>/tls/` | `0700` | `audit:audit` | mTLS client certificate / key for syslog / webhook / loki / Vault. |

`<app>` is the consumer's binary name (e.g. `myservice`,
`payments-api`). The library does NOT prescribe these paths; they
work as defaults and fail loudly to the operator if not honoured.

The application binary itself runs as a dedicated UID — typically
`audit` or the consumer's service UID — and reads `outputs.yaml` and
the secret files. It does NOT need write access to `/etc/<app>/`;
only `/var/log/<app>/` (file output) and any TLS-cert temporary
storage.

## Secret Injection

Audit credentials (HMAC salts, webhook bearer tokens, Vault tokens,
basic-auth passwords) MUST NOT live in `outputs.yaml`. The library
resolves them at startup via three mechanisms — pick whichever fits
your platform:

| Mechanism | YAML syntax | Best for |
|---|---|---|
| Environment variable | `salt.value: "${HMAC_SALT}"` | systemd `Environment=`, Docker `--env`, Kubernetes env-from-Secret. Same-UID readable via `/proc/PID/environ`. |
| File reference | `salt.value: "ref+file:///etc/myservice/secrets/hmac-salt"` | Kubernetes mounted Secrets, on-disk credentials managed by configuration management. Path must be absolute; symlinks are followed. |
| Env reference | `salt.value: "ref+env://HMAC_SALT"` | Same as env var but composes with the `ref+` registry; interchangeable with the bare-`${VAR}` form. |
| Vault / OpenBao | `salt.value: "ref+vault://kv/audit#salt"` | Centralised secret stores with rotation, audit logging, and TTL'd dynamic credentials. See [secrets.md](secrets.md). |

The library best-effort zeroes provider `[]byte` token storage on
`Provider.Close()` but cannot zero Go strings (they are immutable);
see [SECURITY.md §Secrets and Memory Retention](../SECURITY.md#secrets-and-memory-retention)
and [docs/threat-model.md](threat-model.md) for the full memory model.

## systemd Unit

A production-grade unit file with sandboxing primitives. Adapt
paths to your binary and config.

```ini
# /etc/systemd/system/myservice.service
[Unit]
Description=MyService — audited application
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=audit
Group=audit

# Read-only application install
ExecStart=/usr/bin/myservice

# Config + secret material
Environment=AUDIT_CONFIG_PATH=/etc/myservice/outputs.yaml
EnvironmentFile=-/etc/myservice/myservice.env

# Hardening — minimise the blast radius if the service is compromised
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
PrivateTmp=yes
PrivateDevices=yes
PrivateUsers=yes
NoNewPrivileges=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

# Audit-specific writable paths — the only directories the service may write
ReadWritePaths=/var/log/myservice

# Capability removal — service binds :8080 (>1024) so it needs none
CapabilityBoundingSet=
AmbientCapabilities=

# Disable core dumps so secrets in memory don't end up on disk
LimitCORE=0

# Resource limits
TasksMax=512
LimitNOFILE=65536

# Restart policy
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

`/etc/myservice/myservice.env` carries the secrets that the
application needs as env vars — readable only by `audit:audit`
(`chmod 0600`):

```bash
HMAC_SALT=...
WEBHOOK_BEARER=...
VAULT_TOKEN=...
```

`AUDIT_CONFIG_PATH` is the application's own convention; the audit
library doesn't read this env var directly. Your `main.go` passes
the path to `outputconfig.New(ctx, taxonomyYAML, os.Getenv("AUDIT_CONFIG_PATH"))`.

## Kubernetes Manifests

A complete deployment set: ConfigMap (taxonomy is embedded; this is
just `outputs.yaml`), Secret (HMAC salt + webhook token), PVC for
file-output destination if used, Deployment, NetworkPolicy.

```yaml
# myservice-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: myservice-audit-outputs
data:
  outputs.yaml: |
    version: 1
    app_name: myservice
    host: "${HOSTNAME}"
    outputs:
      console:
        type: stdout
      audit_log:
        type: file
        file:
          path: /var/log/myservice/audit.log
          # Default mode is 0o600 (owner only). Set group_readable:
          # true for 0o640 when a SIEM forwarder runs in the same
          # group.
          max_size_mb: 100
          max_backups: 5
        hmac:
          enabled: true
          salt:
            version: v1
            value: "${HMAC_SALT}"
          algorithm: HMAC-SHA-256
---
apiVersion: v1
kind: Secret
metadata:
  name: myservice-audit-secrets
type: Opaque
stringData:
  HMAC_SALT: replace-me-in-production-32-bytes-min
  WEBHOOK_BEARER: replace-me
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: myservice-audit-log
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 10Gi
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myservice
spec:
  replicas: 3
  selector:
    matchLabels: {app: myservice}
  template:
    metadata:
      labels: {app: myservice}
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: myservice
          image: registry.example.com/myservice:v1.0.0
          imagePullPolicy: IfNotPresent
          env:
            - name: AUDIT_CONFIG_PATH
              value: /etc/myservice/outputs.yaml
            - name: HOSTNAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
          envFrom:
            - secretRef:
                name: myservice-audit-secrets
          ports:
            - containerPort: 8080
              name: http
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          volumeMounts:
            - name: audit-config
              mountPath: /etc/myservice
              readOnly: true
            - name: audit-log
              mountPath: /var/log/myservice
            - name: tmp
              mountPath: /tmp
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 1
              memory: 512Mi
      volumes:
        - name: audit-config
          configMap:
            name: myservice-audit-outputs
        - name: audit-log
          persistentVolumeClaim:
            claimName: myservice-audit-log
        - name: tmp
          emptyDir: {}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: myservice-audit-egress
spec:
  podSelector:
    matchLabels: {app: myservice}
  policyTypes: [Egress]
  egress:
    # DNS
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels: {k8s-app: kube-dns}
      ports:
        - {protocol: UDP, port: 53}
        - {protocol: TCP, port: 53}
    # Loki / SIEM (replace selector with your environment)
    - to:
        - podSelector:
            matchLabels: {app: loki}
      ports:
        - {protocol: TCP, port: 3100}
```

Key choices:

- **`runAsNonRoot: true`** + UID 65532 (non-root) — the library does
  NOT need any capability beyond binding ports >1024.
- **`readOnlyRootFilesystem: true`** — the only writable mount is
  `/var/log/myservice`. The library does not write outside its
  configured file outputs.
- **`automountServiceAccountToken: false`** — audit pods do not call
  the Kubernetes API.
- **`fsGroup: 65532`** — ensures the PVC is writable by the service
  UID without `chown`.
- **NetworkPolicy egress** — pinned to the Loki / webhook target. If
  you set `allow_private_ranges: true` on a Loki/webhook output, the
  NetworkPolicy is what limits the blast radius; see the per-output
  Production Checklists ([webhook](webhook-output.md#production-configuration),
  [loki](loki-output.md#security)).

## Docker Compose

For staging or a single-node production deploy. Mount `outputs.yaml`
read-only and pass secrets via `env_file`.

```yaml
services:
  myservice:
    image: registry.example.com/myservice:v1.0.0
    user: "65532:65532"
    read_only: true
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    environment:
      AUDIT_CONFIG_PATH: /etc/myservice/outputs.yaml
      HOSTNAME: "${HOSTNAME}"
    env_file:
      - ./myservice.env  # HMAC_SALT, WEBHOOK_BEARER, …
    volumes:
      - ./outputs.yaml:/etc/myservice/outputs.yaml:ro
      - audit-log:/var/log/myservice
      - /tmp/myservice:/tmp
    ports:
      - "8080:8080"
    restart: unless-stopped

volumes:
  audit-log:
```

## Container Hardening

The defaults the per-platform examples above already set, summarised:

| Property | Value | Why |
|---|---|---|
| User | non-root (65532 / `audit`) | Limits the blast radius. The library doesn't need root. |
| Capabilities | `drop: [ALL]` | The library binds no privileged ports and uses no kernel features that need a capability. |
| Root filesystem | read-only | Defence in depth — a compromised process cannot write to `/etc`, `/usr`, `/lib`. |
| `/tmp` | tmpfs / emptyDir | Some Go libraries use `os.CreateTemp`; provide a writable scratch. |
| Core dumps | disabled (`LimitCORE=0`) | Secrets in memory MUST NOT end up on disk after a crash. |
| seccomp | RuntimeDefault / `@system-service` | Reduces the syscall surface to the documented Go runtime needs. |
| ServiceAccount token | not mounted | The audit library never calls the Kubernetes API. |

These defaults compose with the library's own threat-model
[non-guarantees](threat-model.md#non-guarantees) — process-memory
inspection by a co-located attacker is mitigated at the OS layer, not
by the library.

## File Output Parent-Directory Behaviour

The file output **does NOT create the parent directory**, and the
internal rotation writer **rejects symlinks at the destination
path**. Both decisions are deliberate:

- **Not creating the parent** keeps the library deterministic and
  audit-trail-friendly. The library does not implicitly mkdir into
  arbitrary paths.
- **Rejecting symlinks** prevents a path-traversal attack where a
  symlinked component (`/var/log` → `/var/log.old/myservice` or
  worse) could redirect writes into a directory the operator did
  not authorise.

The two checks fire at different points in the lifecycle, and the
operator-grep fragments differ:

| When | Symptom (error string fragment) | Root cause | Resolution |
|---|---|---|---|
| At `audit.New` / `outputconfig.New` (construction) | `audit/file: output parent directory "/var/log/myservice": stat /var/log/myservice: no such file or directory` | Parent dir was never created. | Create the directory in the deploy step (see commands below). The auditor will not start until this is fixed. |
| On the first audit event (rotation writer's `safeOpen`) | `rotate: "/var/log/myservice/audit.log" is a symlink` | The destination path itself is a symlink (often a leftover from a previous deploy or a manual `ln -s`). | Remove the symlink and let the rotation writer create the regular file. |
| On the first audit event (rotation writer's `safeOpen`) | `rotate: "<directory-component>" is a symlink` | A component of the path is a symlink (commonly `/var/log` itself on systems with `/var/log → /data/var/log`). | Eliminate the symlink (use the resolved real path) OR move the file output destination to a path with no symlinked components. |

Construction succeeds when the parent directory exists; the symlink
rejection runs lazily on first write inside the rotate writer. A CI
smoke test that only constructs the auditor will not catch the
symlink case — exercise an end-to-end audit event in any pre-deploy
test that targets the file output.

### systemd: ExecStartPre

```ini
[Service]
ExecStartPre=/bin/mkdir -p /var/log/myservice
ExecStartPre=/bin/chown audit:audit /var/log/myservice
ExecStartPre=/bin/chmod 0750 /var/log/myservice
ExecStart=/usr/bin/myservice
```

Use `+` prefix to elevate privileges only for the pre-start steps:

```ini
ExecStartPre=+/bin/mkdir -p /var/log/myservice
ExecStartPre=+/bin/chown audit:audit /var/log/myservice
```

### Kubernetes: initContainer

```yaml
initContainers:
  - name: prepare-audit-log
    image: registry.example.com/myservice:v1.0.0
    command: [/bin/sh, -c]
    args:
      - |
        mkdir -p /var/log/myservice
        chown 65532:65532 /var/log/myservice
        chmod 0750 /var/log/myservice
    securityContext:
      runAsUser: 0           # initContainer needs root to chown
      runAsNonRoot: false
      capabilities:
        add: [CHOWN, FOWNER]
        drop: [ALL]
    volumeMounts:
      - name: audit-log
        mountPath: /var/log/myservice
```

If your PVC has a `subPath`, the parent inside the PVC must already
exist — `mkdir -p` covers this. If your PVC is mounted via a
StorageClass that supports `fsGroup`, you may not need the
initContainer at all.

### Symlinked `/var/log/audit`

`/var/log` itself is sometimes a symlink (e.g. `/var/log → /data/var/log`
on systems with separate `/data` partitions). The library's symlink
rejection applies to every component of the resolved parent. Two
options:

- **Use the real path in `outputs.yaml`** —
  `path: /data/var/log/myservice/audit.log`. The library's path
  validation runs on the literal string you provide.
- **Eliminate the symlink** — bind-mount or restructure the
  filesystem so `/var/log/myservice` resolves directly without
  traversing a symlink. Common in container deployments where the
  PVC is mounted at `/var/log/myservice` directly.

### Why no `create_parent: true` flag

The issue raising this guide considered adding a YAML flag that
would mkdir the parent. We chose not to:

- Implicit mkdir into operator-controlled paths is a path-traversal
  surface — even with allowlist checks, the complexity is hard to
  justify against the one-line `ExecStartPre` / `initContainer` fix.
- Audit trails MUST be explicit. The deployment manifest documenting
  `mkdir -p /var/log/myservice` is itself a useful artefact for
  compliance reviewers; an implicit library-side mkdir hides that
  intent.
- The current behaviour is deterministic: the operator gets the same
  error every time, on the same line, with the same resolution.

## Capacity Planning

The two parameters that govern throughput are
[`auditor.queue_size`](output-configuration.md#auditor-configuration)
(events between the application and the drain goroutine) and the
per-output `buffer_size` (events between the drain goroutine and the
output's `Write` call). They are documented in detail in
[docs/async-delivery.md](async-delivery.md); this section gives you
the operator-facing numbers.

### Sizing formulae

```
queue_size  > peak_event_rate × max_drain_latency
buffer_size > peak_event_rate × max_output_write_duration × 2
```

`max_drain_latency` is the time between an event being enqueued and
the drain goroutine picking it up — bounded by your `GOMAXPROCS` and
the cost of `Audit` / `format` / fan-out. On a modern x86 server with
GOMAXPROCS=8 this is sub-millisecond at <100k events/s.

`max_output_write_duration` is the time the slowest output's `Write`
takes to return — for stdout / file ≈ 1 ms, for syslog ≈ 5 ms, for
HTTP outputs (webhook / loki) up to `Config.Timeout` (default 10 s).
The 2× factor absorbs retry latency on transient downstream failures.

### Tier table

| Event rate | `auditor.queue_size` | Per-output `buffer_size` | `auditor.shutdown_timeout` | Notes |
|---|---|---|---|---|
| <100/s (typical line-of-business app) | 10 000 (default) | 10 000 (default) | 5 s | Defaults work. No tuning required. |
| 1 000/s (medium-traffic API or auth gateway) | 10 000 | 10 000 | 10 s | One web-tier instance. Watch `OutputMetrics.RecordDrop` — it should be zero. |
| 10 000/s (high-traffic API / payment gateway) | 50 000 | 25 000 | 15 s | Multiple web-tier instances. Pre-warm the buffer pool by emitting a few events at startup. Profile under realistic load. |
| 100 000/s (specialised pipeline) | 100 000 (max practical for in-process) | 100 000 | 30 s | At this rate consider a syslog-relay or Loki-agent sidecar; in-process buffering is no longer the bottleneck — network egress is. |

The defaults (`queue_size: 10000`, per-output `buffer_size: 10000`,
`shutdown_timeout: 5s`) are tuned for the <100/s tier and continue
to absorb 1 000/s without changes. Above that rate, **measure**
before tuning: `OutputMetrics.RecordDrop` /
`audit.Metrics.RecordBufferDrop` returning non-zero is the signal
that you've underprovisioned.

A 24-hour soak under realistic peak load with HMAC enabled and at
least two outputs is the recommended gate before promoting to
production at the 10 000/s tier or higher.

## Pre-Deploy Validation

The `audit-validate` CLI parses your `outputs.yaml` against the
schema the library uses at startup and exits with a class-coded
error if anything is wrong. Run it as a CI gate before deployment:

```bash
go install github.com/axonops/audit/cmd/audit-validate@latest

audit-validate -taxonomy taxonomy.yaml -outputs prod-outputs.yaml
echo $?  # 0 valid, 1 parse, 2 schema, 3 semantic
```

In CI:

```yaml
- name: Validate audit configuration
  run: |
    audit-validate \
      -taxonomy go-audit/taxonomy.yaml \
      -outputs deploy/outputs.yaml
```

`ref+vault://` / `ref+openbao://` / `ref+file://` / `ref+env://`
references are rejected by the default release binary as semantic
errors (exit 3) — the offline binary has no providers compiled in.
This is deliberate: a CI gate that resolves live secrets would
require the CI runner to authenticate to your secret store. If you
need full offline validation including secret resolution, build a
custom validator binary that blank-imports the relevant
`secrets/...` sub-modules. See [docs/validation.md](validation.md)
for the recipe.

## Further Reading

- [SECURITY.md](../SECURITY.md) — disclosure policy, scope.
- [docs/threat-model.md](threat-model.md) — actors, assets, trust
  boundaries, guarantees, non-guarantees.
- [docs/outputs.md § Failure Mode Matrix](outputs.md#failure-mode-matrix)
  — concrete behaviour per output × failure mode (down, slow, auth
  failure, disk full, TLS expired, DNS, rate-limited) with the
  metric counter and operator action for every cell.
- [docs/output-configuration.md](output-configuration.md) — full
  `outputs.yaml` reference.
- [docs/async-delivery.md](async-delivery.md) — buffering
  architecture, drop semantics, shutdown.
- [docs/secrets.md](secrets.md) — secret-provider authentication and
  rotation.
- [docs/writing-custom-secret-providers.md](writing-custom-secret-providers.md)
  — worked example, registration, and security checklist for
  backends not covered by the built-in providers (Vault,
  OpenBao, file, env).
- [deploy/grafana/](../deploy/grafana/) — production-ready Grafana
  dashboards (Loki-sourced events + Prometheus-sourced pipeline
  health) shipped as release artefacts; import via Grafana UI
  upload or the provisioning directory.
- [docs/validation.md](validation.md) — `audit-validate` CLI.
- [docs/metrics-monitoring.md § Health Endpoint](metrics-monitoring.md#health-endpoint)
  — `/healthz` and `/readyz` handler patterns for Kubernetes
  liveness and readiness probes.
- [examples/17-capstone/](../examples/17-capstone/) — complete
  deployment example with Postgres, Loki, Prometheus, graceful
  shutdown.
- [examples/18-health-endpoint/](../examples/18-health-endpoint/) —
  runnable `/healthz` and `/readyz` example driven by audit
  introspection.
