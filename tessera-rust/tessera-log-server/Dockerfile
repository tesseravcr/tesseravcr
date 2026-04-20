# Multi-stage build for tessera-log-server
# Stage 1: Build
FROM rust:alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

WORKDIR /build

# Copy entire workspace (build from repo root)
COPY tessera-rust/tessera ./tessera
COPY tessera-rust/tessera-log-server ./tessera-log-server

# Build release binary
WORKDIR /build/tessera-log-server
RUN cargo build --release

# Stage 2: Runtime
FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache ca-certificates wget

# Create non-root user
RUN addgroup -g 1000 tessera && \
    adduser -D -u 1000 -G tessera tessera

# Copy binary from builder
COPY --from=builder /build/tessera-log-server/target/release/tessera-log-server /usr/local/bin/

# Create data directory
RUN mkdir -p /data && chown tessera:tessera /data

USER tessera
WORKDIR /data

# Default environment
ENV TESSERA_DB=/data/tessera-log.db \
    TESSERA_KEY_FILE=/data/operator.key \
    TESSERA_BIND=0.0.0.0:7800 \
    TESSERA_LOG_LEVEL=info

EXPOSE 7800

ENTRYPOINT ["tessera-log-server"]
