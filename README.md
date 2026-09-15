# Struct Framework

<p align="center">
  <strong>Production-ready, typed-first Go microservice framework featuring Clean Architecture, dual PostgreSQL & MySQL wire protocols, WebAuthn passkeys, TOTP MFA, Prometheus observability, and high-performance CLI tooling.</strong>
</p>

<p align="center">
  <a href="https://struct-kit.github.io/docs/"><img src="https://img.shields.io/badge/docs-web%20portal-6366f1.svg" alt="Documentation Portal"></a>
  <img src="https://img.shields.io/badge/go-1.27-blue.svg" alt="Go Version">
  <img src="https://img.shields.io/badge/architecture-clean%20mvc-06b6d4.svg" alt="Architecture">
  <img src="https://img.shields.io/badge/storage-postgres%20%7C%20mysql%20%7C%20memory-10b981.svg" alt="Databases">
  <img src="https://img.shields.io/badge/security-webauthn%20%7C%20totp%20%7C%20jwt-purple.svg" alt="Security">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
</p>

---

## 🌐 Documentation Suite

- 🌐 **[Interactive Web Documentation](https://struct-kit.github.io/docs/)** (or [local docs/index.html](docs/index.html)): The primary interactive portal featuring interactive API route inspection, architecture visualizers, copyable code tutorials, active ScrollSpy, and mobile-ready responsive UX.
- 📖 **[Framework Architecture Guide](docs/FRAMEWORK_GUIDE.md)**: In-depth manual on Clean Architecture invariants, layering boundaries, request lifecycle (`appctx`), typed errors (`apperr`), message brokers, and security models.
- 📡 **[API Reference](docs/API_REFERENCE.md)**: Complete HTTP API specification detailing JSON payloads, Bearer token authentication headers, error codes, and curl examples.
- 💻 **[CLI Reference](docs/CLI_REFERENCE.md)**: Full manual for the `struct` CLI tool, component scaffolding (`struct make`), and database migration commands.
- 📋 **[Technical Documentation](docs/DOCUMENTATION.md)**: Exhaustive reference covering all configuration options, route declarations, and package internals.

> **Verification Status**: Builds cleanly on Go 1.27 (`make build`), passes `go vet ./...` with zero warnings, and passes 100% of unit and integration tests under the Go race detector (`make test` / `make check`).

---

## 🚀 Key Framework Features

1. **Clean Layering & Decoupling**:
   - Strict separation between Domain (`internal/mvc`) and Platform (`internal/platform`).
   - Platform packages never import business logic or controllers.
   - Interfaces decouple persistence, authentication, and event emission.

2. **Enterprise Security & Authentication**:
   - **Argon2id & PBKDF2** password hashing with 15-minute brute-force lockout protection.
   - **FIDO2 / WebAuthn Passkeys**: Complete registration and assertion ceremonies for passwordless authentication and hardware MFA.
   - **RFC 6238 TOTP**: QR-code enrollment (`otpauth://`), authenticator verification, and single-use SHA-256 hashed backup codes.
   - **HTTP Bearer Token Middleware**: Dedicated `RequireAuth` and `RequireAuthenticated` middleware with HS256 JWT access tokens and rotating refresh tokens.

3. **Dual Native Database Protocols**:
   - Custom zero-overhead wire protocols for **PostgreSQL 18** and **MySQL 9**.
   - Built-in connection pooling, parameterized query execution, and transactions.
   - **Read Replica Routing**: Isolate heavy analytical and reporting queries using `DATABASE_REPLICA_URL`.
   - **In-Memory Mode**: Zero external infrastructure required for local development and rapid test suites.

4. **Developer Experience & `struct` CLI**:
   - **Full Stack Scaffolding**: `struct make resource <Name>` generates model, DTO, service, repositories (both dialects), controller, and unit test in one command.
   - **Database Migrations**: `struct migrate create`, `up`, `down`, and `status` with crash-safe dirty-flag tracking in `schema_migrations`.
   - **Offline Route Inspection**: `struct routes` prints the complete route table without binding a network socket.

5. **Observability & Resilience**:
   - **Prometheus Metrics**: High-efficiency metrics registry at `/metrics` (request duration histograms, throughput counters, Go runtime stats).
   - **Distributed Tracing**: W3C `traceparent` context propagation and standard OpenTelemetry Protocol (OTLP/HTTP JSON) span export.
   - **Unified Request Context (`appctx`)**: Strongly typed correlation metadata (`TraceID`, `RequestID`, `UserID`, `ClientIP`) enriched into structured `log/slog` entries.
   - **Resilient RPC Client**: Deadlines, exponential backoff retries, circuit breaker, bulkhead concurrency limits, and client-side load balancing.
   - **Transactional Outbox Pattern**: Atomic database writes and asynchronous message publishing across Redis, NATS, Kafka, or log sinks.

6. **Production Container Deployment**:
   - Distroless non-root runtime (`gcr.io/distroless/static-debian13:nonroot`) with dropped capabilities and read-only filesystem.
   - Automated Linux cgroup v1/v2 CPU quota detection for optimal `GOMAXPROCS` tuning.
   - Build cache acceleration (`--mount=type=cache`) and multi-architecture compilation (`amd64` / `arm64`).

---

## 📦 Project Layout

```
cmd/
  ├── api/              # HTTP composition root (wires dependencies, binds port)
  └── struct/           # Operational CLI entrypoint (codegen, migrations, doctor, relay)
internal/
  ├── app/              # Application Composition Root: Build(), Routes(), DI wiring
  │     └── cli/        # CLI subcommands (make, migrate, doctor, serve, relay, report)
  ├── mvc/              # Domain & Presentation Layer
  │     ├── models/     # Domain entities (User, Passkey, Credentials)
  │     ├── services/   # Business logic (UserService, AuthService)
  │     ├── controllers/# HTTP handlers & error renderers
  │     ├── views/      # Response DTOs
  │     └── apperr/     # Typed domain error hierarchy
  ├── platform/         # Pure Infrastructure Layer (Never imports internal/mvc)
  │     ├── config/     # Strict environment loader (PostgreSQL, MySQL, Broker, Keys)
  │     ├── http/       # Router, middleware chain, and appctx RequestContext
  │     ├── store/      # Interchangeable store.Driver: PostgreSQL & MySQL native wire protocols
  │     ├── security/   # Authn (JWT), TOTP (RFC 6238), WebAuthn passkeys, Authz policies
  │     ├── events/     # Domain events, Message Broker factory, and Outbox Relay
  │     ├── logging/    # Context-aware slog with automatic PII redaction
  │     ├── metrics/    # Prometheus registry & Go runtime collector
  │     ├── tracing/    # W3C Traceparent parser & OTLP HTTP span exporter
  │     └── procs/      # cgroup v1/v2 container CPU quota reader
  └── support/          # Cryptography, validation, and in-process job runners
docker/                 # Hardened Dockerfile & docker-compose.yml
docs/                   # Interactive HTML documentation and guides
migrations/             # Timestamped up/down SQL migrations for postgres and mysql
tests/                  # Comprehensive race-detector verified unit & integration tests
```

---

## ⚡ Quickstart

### 1. In-Memory Mode (Zero Infrastructure)

Run immediately with zero external dependencies:

```bash
make check          # runs gofmt, go vet, and tests with race detection
make run            # boots API server in development mode on :8080
```

### 2. Full Stack with Docker Compose (PostgreSQL, MySQL, Redis)

```bash
# 1. Spin up supporting containers (Postgres 18, MySQL 9, Redis 8)
make compose-up

# 2. Configure environment (PostgreSQL)
export DB_DRIVER=postgres
export DATABASE_URL="postgres://svc:secret@127.0.0.1:5432/svc?sslmode=disable"

# 3. Verify environment and database connectivity
go run ./cmd/struct doctor

# 4. Apply database migrations
go run ./cmd/struct migrate up

# 5. Start API server
make run
```

### 3. Switching to MySQL via Environment Variables

No code changes required—simply configure the environment variables:

```bash
export DB_DRIVER=mysql
export DATABASE_URL="mysql://svc:secret@127.0.0.1:3306/svc"

go run ./cmd/struct doctor
go run ./cmd/struct migrate up
make run
```

Alternatively, configure discrete 12-factor credentials without a connection string:
```bash
export DB_DRIVER=postgres
export DB_HOST=127.0.0.1
export DB_PORT=5432
export DB_USER=svc
export DB_PASSWORD=secret
export DB_NAME=svc
export DB_SSLMODE=disable
```

---

## 🛠️ Operational CLI (`struct`)

```bash
# --- Diagnostics & Inspection ---
struct serve                   # Boots HTTP API server
struct routes                  # Inspects declarative route table (offline, no socket)
struct health                  # Probes local /readyz endpoint
struct doctor                  # Verifies environment, DB connectivity, and i18n catalogs
struct version                 # Displays version, git commit, and Go compiler metadata
struct lint                    # Runs framework layering and code invariant linter

# --- Code Generation (struct make) ---
struct make resource Invoice   # Scaffolds Model + DTO + Service + Repositories + Controller
struct make model Order        # Scaffolds domain model with validation tags
struct make controller Order   # Scaffolds controller + unit test
struct make service Order      # Scaffolds service interface + in-memory implementation
struct make repository Order   # Scaffolds both PostgreSQL and MySQL repositories
struct make dto Order          # Scaffolds request/response DTO under internal/mvc/views
struct make enum OrderStatus --values=draft,paid,cancelled
struct make policy Order       # Scaffolds deny-by-default authz policy + unit test
struct make event OrderPlaced  # Scaffolds versioned domain event + consumer
struct make job SendEmail      # Scaffolds asynchronous background queue worker
struct make locale de          # Scaffolds new locale translation catalog
struct make rpc BillingService # Scaffolds internal RPC client + handler stub

# --- Database Migrations (struct migrate) ---
struct migrate create add_orders_table  # Generates paired .up.sql / .down.sql files
struct migrate up                       # Applies all pending migrations against DATABASE_URL
struct migrate down                     # Rolls back the most recently applied migration
struct migrate status                   # Displays applied vs pending migration status

# --- Background Daemons & Analytics ---
struct relay                            # Runs standalone transactional outbox polling relay
struct report signups                   # Executes aggregate SQL report over the last 30 days
```

---

## 🔒 Authentication & API Usage Examples

### User Registration & Login

```bash
# 1. Register a new user account:
curl -X POST http://localhost:8080/v1/users \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"secure-password-123","locale":"en"}'

# 2. Authenticate with credentials:
curl -X POST http://localhost:8080/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"secure-password-123"}'

# Returns:
# {"access_token":"eyJhbGciOi...","refresh_token":"d8f1e9c2..."}
```

### Accessing Protected Routes with Bearer Token

```bash
# 3. Call protected endpoint using the Authorization Bearer header:
curl -X GET http://localhost:8080/v1/auth/passkeys \
  -H "Authorization: Bearer <access_token>"

# 4. Revoke all active user sessions:
curl -X POST http://localhost:8080/v1/auth/logout-all \
  -H "Authorization: Bearer <access_token>"
```

### TOTP Multi-Factor Authentication (MFA)

```bash
# 1. Enroll TOTP authenticator app (Requires Bearer token):
curl -X POST http://localhost:8080/v1/auth/totp/enroll \
  -H "Authorization: Bearer <access_token>"
# -> {"secret":"JBSWY3DPEHPK3PXP","otpauth_uri":"otpauth://totp/Struct:alice@example.com?..."}

# 2. Confirm enrollment with 6-digit authenticator code:
curl -X POST http://localhost:8080/v1/auth/totp/confirm \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"code":"123456"}'
# -> {"backup_codes":["ABCDE-12345", ...]}

# 3. Subsequent logins require redeeming the MFA ticket:
curl -X POST http://localhost:8080/v1/auth/mfa/totp \
  -H "Content-Type: application/json" \
  -d '{"ticket":"<mfa_ticket>","code":"123456"}'
```

### Passwordless Passkey (WebAuthn) Login

```bash
# 1. Begin passkey authentication ceremony:
curl -X POST http://localhost:8080/v1/auth/passkeys/login/begin \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com"}'

# 2. Finish assertion verification with signed authenticator data:
curl -X POST http://localhost:8080/v1/auth/passkeys/login/finish \
  -H "Content-Type: application/json" \
  -d '{
    "ceremony_id":"...",
    "credential_id":"...",
    "client_data_json":"<base64url>",
    "authenticator_data":"<base64url>",
    "signature":"<base64url>"
  }'
```

---

## ⚙️ Configuration Reference

All settings flow through `internal/platform/config` and are configurable via environment variables:

| Variable | Default | Dialects / Values | Description |
|---|---|---|---|
| `APP_ENV` | `development` | `development`, `production`, `test` | Enforces production requirements (mandatory keys, disabled pprof). |
| `APP_NAME` | `struct-framework` | String | Application display name reported in health probes. |
| `PORT` | `8080` | Integer | HTTP listener TCP port. |
| `DB_DRIVER` | `memory` | `postgres`, `mysql`, `memory` | Backing storage driver (also accepts `DATABASE_DRIVER`, `DB_TYPE`). |
| `DATABASE_URL` | `""` | Connection URL | Connection string (`postgres://...` or `mysql://...`). |
| `DATABASE_REPLICA_URL`| `""` | Connection URL | Optional read replica URL for isolating aggregate reporting queries. |
| `DB_MAX_OPEN_CONNS` | `25` | Integer | Maximum open connections in the pool. |
| `DB_MAX_IDLE_CONNS` | `10` | Integer | Maximum idle connections in the pool. |
| `DB_CONN_MAX_LIFETIME`| `15m` | Duration | Maximum connection reuse duration. |
| `MESSAGE_BROKER` | `memory` | `memory`, `redis`, `nats`, `kafka`, `log` | Pluggable pub/sub broker driver for domain events. |
| `BROKER_URL` | `""` | String URL | Broker connection string (e.g. `redis://localhost:6379`). |
| `OUTBOX_RELAY_ENABLED`| `false` | Boolean | Runs the transactional outbox relay embedded inside the API server. |
| `OTEL_EXPORTER_OTLP_ENDPOINT`| `""` | HTTP URL | OpenTelemetry Protocol endpoint (e.g. `http://localhost:4318/v1/traces`). |
| `JWT_SIGNING_KEY` | *(ephemeral dev)* | 32+ bytes | HMAC-SHA256 secret for token issuance (mandatory in production). |
| `ENCRYPTION_KEY` | *(ephemeral dev)* | 32 bytes | AES-256 key for TOTP secret encryption at rest (mandatory in production). |
| `DEFAULT_LOCALE` | `en` | Language code | Default language for response messages. |
| `SUPPORTED_LOCALES` | `en` | Comma-separated | Supported language tags (e.g. `en,es,de,fr`). |
| `WEBAUTHN_RP_ID` | `localhost` | Hostname / Domain | Relying Party identifier for WebAuthn passkeys. |
| `WEBAUTHN_ORIGIN` | `http://localhost:8080` | Origin URL | Exact scheme + host + port reported by the browser. |
| `RATE_LIMIT_RPS` | `20` | Integer | Requests per second per IP allowed by the sharded rate limiter. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` | Output verbosity for context-aware structured slog logger. |
| `PPROF_ENABLED` | `true` (dev) | Boolean | Mounts `/debug/pprof/*` diagnostic endpoints. |

---

## 🧪 Testing & Verification

```bash
# Run format checking, static analysis, and uncached race tests:
make check

# Run uncached unit tests with race detection:
go test -count=1 -p 1 -race -cover ./tests/...

# Compile binaries:
make build
```

---

## 🐳 Docker Deployment

The production image uses a multi-stage distroless build with cgroup v2 container quota detection:

```bash
# Build production Docker container:
docker build -t struct-framework:latest -f docker/Dockerfile .

# Start complete multi-container stack:
make compose-up

# Tear down:
make compose-down
```

---

## 🏛️ Tech Stack

- **Language**: Go 1.27
- **Primary Databases**: PostgreSQL 18 & MySQL 9 (Native Wire Protocols)
- **Message Brokers**: Redis 8, NATS, Apache Kafka, In-Memory
- **Runtime Security**: FIDO2 / WebAuthn, RFC 6238 TOTP, Argon2id, AES-256-GCM, HS256 JWT
- **Observability**: Prometheus text exposition, W3C Trace Context, OTLP/HTTP JSON

---

## 📜 License & Author

Built with MIT License — see the [LICENSE](LICENSE) file for details.

Developed by: **Loai Kanou**  
- **Repository**: [github.com/orgs/struct-kit/framework](https://github.com/orgs/struct-kit/framework)  
- **Documentation**: [struct-kit.github.io/docs](https://struct-kit.github.io/docs/)
