# Acknowledgements

audit builds on the work of these open-source projects. We are
grateful to their authors and contributors.

## Runtime Dependencies

| Project | License | Copyright | Used For |
|---------|---------|-----------|----------|
| [github.com/goccy/go-yaml](https://github.com/goccy/go-yaml) | MIT | Masaaki Goshima | YAML parsing for taxonomy and output configuration |
| [github.com/axonops/srslog](https://github.com/axonops/srslog) | BSD-3-Clause | 2015 Rackspace | RFC 5424 syslog client (fork of [gravwell/srslog](https://github.com/gravwell/srslog)) |
| [github.com/axonops/syncmap](https://github.com/axonops/syncmap) | Apache-2.0 | 2023 Richard Gooding; 2026 AxonOps Limited | Generic `sync.Map` for lock-free category lookups (fork of [rgooding/go-syncmap](https://github.com/rgooding/go-syncmap)) |

## Test Dependencies

| Project | License | Copyright | Used For |
|---------|---------|-----------|----------|
| [github.com/stretchr/testify](https://github.com/stretchr/testify) | MIT | 2012-2020 Mat Ryer, Tyler Bunnell and contributors | Test assertions |
| [go.uber.org/goleak](https://github.com/uber-go/goleak) | MIT | 2018 Uber Technologies, Inc. | Goroutine leak detection in tests |
| [github.com/cucumber/godog](https://github.com/cucumber/godog) | MIT | SmartBear | BDD test framework |

## Build and CI Tools

| Tool | License | Used For |
|------|---------|----------|
| [golangci-lint](https://github.com/golangci/golangci-lint) | GPL-3.0 | Static analysis and linting |
| [GoReleaser](https://github.com/goreleaser/goreleaser) | MIT | Release automation |
| [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) | BSD-3-Clause | Vulnerability scanning |

## License Compatibility

All runtime and test dependencies use licenses compatible with
Apache 2.0 (MIT, BSD-3-Clause, Apache-2.0). No GPL-licensed code is
linked into the audit binary — `golangci-lint` is a build tool
only, not a library dependency.
