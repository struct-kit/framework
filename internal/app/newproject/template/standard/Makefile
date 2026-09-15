VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X __MODULE_PLACEHOLDER__/internal/app/cli.Version=$(VERSION) -X __MODULE_PLACEHOLDER__/internal/app/cli.Commit=$(COMMIT)

.PHONY: run build test check fmt vet lint compose-up compose-down

run:
	APP_ENV=development LOG_LEVEL=debug go run ./cmd/api

build:
	go build -trimpath -ldflags="$(LDFLAGS)" -o bin/struct-api ./cmd/api
	go build -trimpath -ldflags="$(LDFLAGS)" -o bin/struct ./cmd/struct

test:
	go test -p 1 -race -cover ./...

fmt:
	gofmt -l .

vet:
	go vet ./...

check: fmt vet test

compose-up:
	docker compose -f docker/docker-compose.yml up --build -d

compose-down:
	docker compose -f docker/docker-compose.yml down
