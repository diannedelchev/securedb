# syntax=docker/dockerfile:1

########## Build stage ##########
FROM golang:1.26.9-alpine AS build
WORKDIR /src

# Cache module downloads between builds (BuildKit).
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/securedb ./cmd/server

########## Runtime stage ##########
FROM alpine:3.21
RUN adduser -D -H securedb && apk add --no-cache ca-certificates tzdata
USER securedb
COPY --from=build /out/securedb /usr/local/bin/securedb

LABEL org.opencontainers.image.title="SecureDB Web Client" \
      org.opencontainers.image.description="Secure browser-based database client: encrypted credentials, RBAC, query policies, approvals, masking, audit trail" \
      org.opencontainers.image.source="https://github.com/diannedelchev/securedb" \
      org.opencontainers.image.licenses="MIT"

EXPOSE 8080
# busybox wget ships with alpine — no extra packages needed.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null 2>&1 || exit 1
ENTRYPOINT ["securedb"]
