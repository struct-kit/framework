# =============================================================================
# STAGE 1: BUILD
# =============================================================================
FROM golang:1.27-alpine AS builder
WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download 2>/dev/null || true

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/struct-api ./cmd/api

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X __MODULE_PLACEHOLDER__/internal/app/cli.Version=${VERSION} -X __MODULE_PLACEHOLDER__/internal/app/cli.Commit=${COMMIT}" \
    -o /out/struct ./cmd/struct

# =============================================================================
# STAGE 2: RUNTIME (distroless, non-root, minimal attack surface)
# =============================================================================
FROM gcr.io/distroless/static-debian13:nonroot AS runtime

LABEL org.opencontainers.image.title="__MODULE_PLACEHOLDER__" \
      org.opencontainers.image.description="High-performance Clean Architecture Go microservice framework" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app
COPY --from=builder /out/struct-api /app/struct-api
COPY --from=builder /out/struct /app/struct
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

USER nonroot:nonroot
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD ["/app/struct", "health"]

ENTRYPOINT ["/app/struct-api"]
