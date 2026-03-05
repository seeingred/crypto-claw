# =============================================================================
# Crypto Claw MPC-TSS Signing Service - Multi-stage Dockerfile
#
# Build specific targets:
#   docker build --target party-a -t crypto-claw-party-a .
#   docker build --target party-b -t crypto-claw-party-b .
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build Go binaries
# ---------------------------------------------------------------------------
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Cache dependency downloads
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build both binaries
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/party-a ./cmd/party-a
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/party-b ./cmd/party-b

# ---------------------------------------------------------------------------
# Stage 2: Party A runtime
# ---------------------------------------------------------------------------
FROM alpine:3.21 AS party-a

RUN apk add --no-cache ca-certificates tzdata curl \
    && addgroup -g 10001 -S cclaw \
    && adduser -u 10001 -S cclaw -G cclaw -h /home/cclaw -s /sbin/nologin

COPY --from=builder /bin/party-a /usr/local/bin/party-a

# Default config and data directories
RUN mkdir -p /etc/crypto-claw /data/crypto-claw \
    && chown -R cclaw:cclaw /etc/crypto-claw /data/crypto-claw

# Configuration can be provided via:
#   1. Mounted config file at /etc/crypto-claw/config.json
#   2. Environment variables (CCLAW_CONFIG_PATH, CCLAW_PASSPHRASE)
ENV CCLAW_CONFIG_PATH=/etc/crypto-claw/config.json
ENV CCLAW_PASSPHRASE=""

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8080/health || exit 1

USER cclaw
WORKDIR /home/cclaw

ENTRYPOINT ["party-a"]
CMD ["-config", "/etc/crypto-claw/config.json", "-passphrase", ""]

# ---------------------------------------------------------------------------
# Stage 3: Party B runtime
# ---------------------------------------------------------------------------
FROM alpine:3.21 AS party-b

RUN apk add --no-cache ca-certificates tzdata curl \
    && addgroup -g 10001 -S cclaw \
    && adduser -u 10001 -S cclaw -G cclaw -h /home/cclaw -s /sbin/nologin

COPY --from=builder /bin/party-b /usr/local/bin/party-b

# Default config and data directories
RUN mkdir -p /etc/crypto-claw /data/crypto-claw \
    && chown -R cclaw:cclaw /etc/crypto-claw /data/crypto-claw

ENV CCLAW_CONFIG_PATH=/etc/crypto-claw/config.json
ENV CCLAW_PASSPHRASE=""

EXPOSE 9443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf --cacert /etc/crypto-claw/ca.pem \
        --cert /etc/crypto-claw/party-b.pem \
        --key /etc/crypto-claw/party-b-key.pem \
        https://localhost:9443/health || exit 1

USER cclaw
WORKDIR /home/cclaw

ENTRYPOINT ["party-b"]
CMD ["-config", "/etc/crypto-claw/config.json", "-passphrase", ""]
