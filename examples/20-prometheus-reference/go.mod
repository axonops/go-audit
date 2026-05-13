module github.com/axonops/audit/examples/20-prometheus-reference

go 1.26.3

replace github.com/axonops/audit => ../..

replace github.com/axonops/audit/file => ../../file

replace github.com/axonops/audit/syslog => ../../syslog

replace github.com/axonops/audit/webhook => ../../webhook

replace github.com/axonops/audit/loki => ../../loki

replace github.com/axonops/audit/outputconfig => ../../outputconfig

replace github.com/axonops/audit/outputs => ../../outputs

replace github.com/axonops/audit/iouring => ../../iouring

replace github.com/axonops/audit/secrets => ../../secrets

replace github.com/axonops/audit/secrets/openbao => ../../secrets/openbao

replace github.com/axonops/audit/secrets/vault => ../../secrets/vault

replace github.com/axonops/audit/secrets/env => ../../secrets/env

replace github.com/axonops/audit/secrets/file => ../../secrets/file

replace github.com/axonops/audit/cmd/audit-gen => ../../cmd/audit-gen

require (
	github.com/axonops/audit v0.1.13
	github.com/axonops/audit/outputconfig v0.1.13
	github.com/axonops/audit/outputs v0.1.13
	github.com/prometheus/client_golang v1.23.2
)

require (
	github.com/axonops/audit/file v0.1.13 // indirect
	github.com/axonops/audit/iouring v0.0.0-20260512203621-dbaeb1c0c180 // indirect
	github.com/axonops/audit/loki v0.1.13 // indirect
	github.com/axonops/audit/secrets v0.1.13 // indirect
	github.com/axonops/audit/secrets/openbao v0.1.13 // indirect
	github.com/axonops/audit/secrets/vault v0.1.13 // indirect
	github.com/axonops/audit/syslog v0.1.13 // indirect
	github.com/axonops/audit/webhook v0.1.13 // indirect
	github.com/axonops/srslog v1.0.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.20.1 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	golang.org/x/sys v0.44.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
