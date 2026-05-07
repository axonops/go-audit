[&larr; Back to README](../README.md)

# Running audit examples — why not the Go Playground?

The Go Playground at <https://play.golang.org> is a sandboxed
environment for sharing snippets of Go code. It does not download
modules from the public proxy, does not expose a filesystem to
user code, and does not allow network access. Several of audit's
hard requirements are incompatible with that sandbox:

- **`go:embed` of generated code.** Most examples use `audit-gen`
  to produce typed event builders from `taxonomy.yaml`. The
  generator's output is a real `.go` file in the same package,
  not a string literal — the Playground's single-file editor
  cannot reproduce this layout.

- **Filesystem-loaded `outputs.yaml`.** Output configuration is
  resolved at runtime from a YAML file the operator supplies.
  The Playground sandbox has no filesystem an operator could
  populate; in-memory loaders are supported via the
  [`outputconfig`](https://pkg.go.dev/github.com/axonops/audit/outputconfig)
  package but are intentionally not the primary path.

- **Multi-module structure.** Outputs that need network I/O
  (`syslog`, `webhook`, `loki`) live in separate modules. The
  Playground only resolves the single module of the snippet
  being run; importing one of those packages would fail at
  resolve time.

To run the examples, clone the repository and follow the readme
in any of the [`examples/`](../examples/) directories — the
shortest is [`examples/01-basic/`](../examples/01-basic/), which
needs only the core module and a few lines of `main.go`. Every
other example builds on it incrementally.

If you need a sharable demo that runs in a browser, prefer
recording a terminal session against `examples/01-basic/` rather
than a Playground link.
