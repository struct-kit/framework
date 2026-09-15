# =============================================================================
# STAGE 1: BUILD
# =============================================================================
FROM golang:1.22-alpine AS builder
WORKDIR /src

RUN apk add --no-cache git ca-certificates

COPY go.mod ./
RUN go mod download 2>/dev/null || true

COPY . .

ARG VERSION=dev
ARG COMMIT=unknown

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/struct-api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -X __MODULE_PLACEHOLDER__/internal/app/cli.Version=${VERSION} -X __MODULE_PLACEHOLDER__/internal/app/cli.Commit=${COMMIT}" \
    -o /out/struct ./cmd/struct

# =============================================================================
# STAGE 2: RUNTIME (distroless, non-root, minimal attack surface)
# =============================================================================
FROM gcr.io/distroless/static-debian12:nonroot AS runtime

WORKDIR /app
COPY --from=builder /out/struct-api /app/struct-api
COPY --from=builder /out/struct /app/struct
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/app/struct-api"]
