// Package config loads all runtime configuration once, at startup, into a
// single strict struct. No other package in this service is permitted to
// call os.Getenv directly — every configurable value flows through Config.
package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the complete, validated runtime configuration for one Struct
// service instance.
type Config struct {
	Env            string
	AppName        string
	AppDescription string
	AppVersion     string
	ServiceName    string
	Port           int

	// DBDriver selects the backing store: "memory" (default, zero external
	// infrastructure), "postgres", or "mysql". DatabaseURL is required when DBDriver
	// is "postgres" or "mysql" — a postgres:// or mysql:// connection URL.
	// DatabaseReplicaURL is optional and routes read-heavy reporting queries to a read replica.
	DBDriver           string
	DatabaseURL        string
	DatabaseReplicaURL string
	DBMaxOpenConns     int
	DBMaxIdleConns     int
	DBConnMaxLifetime  time.Duration

	// BrokerDriver selects the message broker: "memory" (default, in-process),
	// "redis", "nats", "kafka", or "log".
	BrokerDriver string
	BrokerURL    string

	// OutboxRelayEnabled controls whether the outbox relay runs embedded
	// in the API server lifecycle or as a standalone process (struct relay).
	OutboxRelayEnabled bool

	// OTLPEndpoint is an optional OpenTelemetry Protocol (OTLP/HTTP) endpoint (e.g. http://localhost:4318/v1/traces).
	OTLPEndpoint string

	// JWTSigningKey and EncryptionKey are required in production. Outside
	// production they may be left unset; internal/app generates
	// process-lifetime ephemeral keys instead, so local development needs
	// zero extra configuration.
	JWTSigningKey string
	EncryptionKey string

	DefaultLocale    string
	SupportedLocales []string

	// WebAuthnRPID must match the domain passkeys are registered
	// against (e.g. "example.com"); WebAuthnOrigin must match the exact
	// scheme+host+port a browser reports.
	WebAuthnRPID   string
	WebAuthnOrigin string

	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
	RateLimitRPS    int
	LogLevel        string
	PprofEnabled    bool
}

// Load reads every configuration value from the process environment,
// applies defaults, and validates production-only and operational requirements.
func Load() (Config, error) {
	env := getString("APP_ENV", "production")
	isProd := env == "production"

	appName := getString("APP_NAME", getString("SERVICE_NAME", "struct-framework"))

	rawDBURL := getString("DATABASE_URL", "")
	rawDBDriver := getString("DB_DRIVER", getString("DATABASE_DRIVER", getString("DB_TYPE", getString("DATABASE_TYPE", ""))))
	dbDriver := resolveDBDriver(rawDBDriver, rawDBURL)
	databaseURL := resolveDatabaseURL(dbDriver, rawDBURL)
	replicaURL := getString("DATABASE_REPLICA_URL", getString("DB_REPLICA_URL", getString("REPLICA_DATABASE_URL", "")))

	cfg := Config{
		Env:                env,
		AppName:            appName,
		AppDescription:     getString("APP_DESCRIPTION", "Typed-first secure Go microservice framework"),
		AppVersion:         getString("APP_VERSION", "1.0.0"),
		ServiceName:        getString("SERVICE_NAME", appName),
		Port:               getInt("PORT", 8080),
		DBDriver:           dbDriver,
		DatabaseURL:        databaseURL,
		DatabaseReplicaURL: replicaURL,
		DBMaxOpenConns:     getInt("DB_MAX_OPEN_CONNS", 25),
		DBMaxIdleConns:     getInt("DB_MAX_IDLE_CONNS", 10),
		DBConnMaxLifetime:  getDuration("DB_CONN_MAX_LIFETIME", 15*time.Minute),
		BrokerDriver:       getString("MESSAGE_BROKER", getString("BROKER_DRIVER", "memory")),
		BrokerURL:          getString("BROKER_URL", ""),
		OutboxRelayEnabled: getBool("OUTBOX_RELAY_ENABLED", false),
		OTLPEndpoint:       getString("OTEL_EXPORTER_OTLP_ENDPOINT", getString("OTLP_ENDPOINT", "")),
		JWTSigningKey:      getString("JWT_SIGNING_KEY", ""),
		EncryptionKey:      getString("ENCRYPTION_KEY", ""),
		DefaultLocale:      getString("DEFAULT_LOCALE", "en"),
		SupportedLocales:   getStringSlice("SUPPORTED_LOCALES", []string{"en"}),
		WebAuthnRPID:       getString("WEBAUTHN_RP_ID", "localhost"),
		WebAuthnOrigin:     getString("WEBAUTHN_ORIGIN", "http://localhost:8080"),
		ReadTimeout:        getDuration("READ_TIMEOUT", 5*time.Second),
		WriteTimeout:       getDuration("WRITE_TIMEOUT", 10*time.Second),
		ShutdownTimeout:    getDuration("SHUTDOWN_TIMEOUT", 15*time.Second),
		RateLimitRPS:       getInt("RATE_LIMIT_RPS", 20),
		LogLevel:           getString("LOG_LEVEL", "info"),
		PprofEnabled:       getBool("PPROF_ENABLED", !isProd),
	}

	if cfg.DBDriver != "memory" && cfg.DBDriver != "postgres" && cfg.DBDriver != "mysql" {
		return Config{}, fmt.Errorf("config: DB_DRIVER must be \"memory\", \"postgres\", or \"mysql\" (got %q)", cfg.DBDriver)
	}
	if (cfg.DBDriver == "postgres" || cfg.DBDriver == "mysql") && cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("config: DATABASE_URL is required when DB_DRIVER=%s (set DATABASE_URL or DB_HOST/DB_NAME credentials)", cfg.DBDriver)
	}

	validBrokers := map[string]bool{
		"memory": true,
		"log":    true,
		"redis":  true,
		"nats":   true,
		"kafka":  true,
	}
	if !validBrokers[cfg.BrokerDriver] {
		return Config{}, fmt.Errorf("config: MESSAGE_BROKER must be \"memory\", \"log\", \"redis\", \"nats\", or \"kafka\" (got %q)", cfg.BrokerDriver)
	}

	if cfg.DBMaxOpenConns <= 0 {
		return Config{}, fmt.Errorf("config: DB_MAX_OPEN_CONNS must be greater than 0 (got %d)", cfg.DBMaxOpenConns)
	}
	if cfg.DBMaxIdleConns < 0 {
		return Config{}, fmt.Errorf("config: DB_MAX_IDLE_CONNS cannot be negative (got %d)", cfg.DBMaxIdleConns)
	}

	if cfg.Env == "production" {
		if cfg.JWTSigningKey == "" {
			return Config{}, fmt.Errorf("config: JWT_SIGNING_KEY is required when APP_ENV=production")
		}
		if cfg.EncryptionKey == "" {
			return Config{}, fmt.Errorf("config: ENCRYPTION_KEY is required when APP_ENV=production")
		}
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return Config{}, fmt.Errorf("config: PORT %d is out of range", cfg.Port)
	}

	return cfg, nil
}

func (c Config) IsProduction() bool { return c.Env == "production" }

func getString(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func getDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func getBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func getStringSlice(key string, def []string) []string {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

func resolveDBDriver(rawDriver, databaseURL string) string {
	raw := strings.ToLower(strings.TrimSpace(rawDriver))
	switch raw {
	case "postgres", "postgresql", "pgsql", "pg":
		return "postgres"
	case "mysql", "mariadb":
		return "mysql"
	case "memory", "in-memory", "inmemory":
		return "memory"
	}
	if raw == "" {
		trimmedURL := strings.ToLower(strings.TrimSpace(databaseURL))
		if strings.HasPrefix(trimmedURL, "postgres://") || strings.HasPrefix(trimmedURL, "postgresql://") {
			return "postgres"
		}
		if strings.HasPrefix(trimmedURL, "mysql://") {
			return "mysql"
		}
		return "memory"
	}
	return raw
}

func resolveDatabaseURL(driver, dbURL string) string {
	trimmed := strings.TrimSpace(dbURL)
	if trimmed != "" {
		return trimmed
	}
	host := getString("DB_HOST", "")
	name := getString("DB_NAME", getString("DATABASE_NAME", ""))
	if host == "" && name == "" {
		return ""
	}
	user := getString("DB_USER", getString("DATABASE_USER", ""))
	password := getString("DB_PASSWORD", getString("DATABASE_PASSWORD", ""))
	switch driver {
	case "postgres":
		if host == "" {
			host = "localhost"
		}
		port := getString("DB_PORT", "5432")
		if user == "" {
			user = "postgres"
		}
		sslmode := getString("DB_SSLMODE", "disable")
		var auth string
		if password != "" {
			auth = fmt.Sprintf("%s:%s@", url.QueryEscape(user), url.QueryEscape(password))
		} else if user != "" {
			auth = fmt.Sprintf("%s@", url.QueryEscape(user))
		}
		return fmt.Sprintf("postgres://%s%s:%s/%s?sslmode=%s", auth, host, port, name, sslmode)
	case "mysql":
		if host == "" {
			host = "localhost"
		}
		port := getString("DB_PORT", "3306")
		if user == "" {
			user = "root"
		}
		var auth string
		if password != "" {
			auth = fmt.Sprintf("%s:%s@", url.QueryEscape(user), url.QueryEscape(password))
		} else if user != "" {
			auth = fmt.Sprintf("%s@", url.QueryEscape(user))
		}
		return fmt.Sprintf("mysql://%s%s:%s/%s", auth, host, port, name)
	default:
		return ""
	}
}
