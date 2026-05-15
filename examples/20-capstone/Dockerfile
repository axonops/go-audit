# Build stage — fetch dependencies directly from GitHub to avoid
# Go module proxy indexing delays on newly released versions.
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN GOPROXY=direct GONOSUMCHECK=github.com/axonops/audit GONOSUMDB=github.com/axonops/audit go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app .

# Runtime stage — minimal image with just the binary and runtime config.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget
WORKDIR /app
COPY --from=builder /app /app/server
COPY outputs.yaml /app/outputs.yaml
RUN mkdir -p /data
EXPOSE 8080

ENV AUDIT_CONFIG_PATH=/app/outputs.yaml \
    LISTEN_ADDR=:8080 \
    DATABASE_URL=postgres://demo:demo@postgres:5432/audit_demo?sslmode=disable \
    LOKI_URL=http://loki:3100/loki/api/v1/push \
    AUDIT_LOG_PATH=/data/audit.log \
    SECURITY_LOG_PATH=/data/security.log

ENTRYPOINT ["/app/server"]
