package tests

import (
	"os"
	"testing"
	"time"

	"struct-framework/internal/platform/config"
)

func TestConfig_Defaults(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("APP_ENV", "development")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error loading dev defaults: %v", err)
	}

	if cfg.Env != "development" {
		t.Errorf("expected APP_ENV development, got %s", cfg.Env)
	}
	if cfg.AppName != "struct-framework" {
		t.Errorf("expected default AppName struct-framework, got %s", cfg.AppName)
	}
	if cfg.AppVersion != "1.0.0" {
		t.Errorf("expected default AppVersion 1.0.0, got %s", cfg.AppVersion)
	}
	if cfg.Port != 8080 {
		t.Errorf("expected default port 8080, got %d", cfg.Port)
	}
	if cfg.DBDriver != "memory" {
		t.Errorf("expected default DBDriver memory, got %s", cfg.DBDriver)
	}
	if cfg.BrokerDriver != "memory" {
		t.Errorf("expected default BrokerDriver memory, got %s", cfg.BrokerDriver)
	}
	if cfg.ReadTimeout != 5*time.Second {
		t.Errorf("expected default ReadTimeout 5s, got %v", cfg.ReadTimeout)
	}
	if cfg.RateLimitRPS != 20 {
		t.Errorf("expected default RateLimitRPS 20, got %d", cfg.RateLimitRPS)
	}
	if !cfg.PprofEnabled {
		t.Errorf("expected PprofEnabled true in development by default")
	}
}

func TestConfig_CustomAppAndBroker(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("APP_ENV", "development")
	_ = os.Setenv("APP_NAME", "order-service")
	_ = os.Setenv("APP_DESCRIPTION", "Order processing microservice")
	_ = os.Setenv("APP_VERSION", "2.1.0")
	_ = os.Setenv("MESSAGE_BROKER", "redis")
	_ = os.Setenv("BROKER_URL", "redis://localhost:6379")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.AppName != "order-service" {
		t.Errorf("expected AppName order-service, got %s", cfg.AppName)
	}
	if cfg.AppDescription != "Order processing microservice" {
		t.Errorf("expected AppDescription match, got %s", cfg.AppDescription)
	}
	if cfg.AppVersion != "2.1.0" {
		t.Errorf("expected AppVersion 2.1.0, got %s", cfg.AppVersion)
	}
	if cfg.BrokerDriver != "redis" {
		t.Errorf("expected BrokerDriver redis, got %s", cfg.BrokerDriver)
	}
	if cfg.BrokerURL != "redis://localhost:6379" {
		t.Errorf("expected BrokerURL match, got %s", cfg.BrokerURL)
	}
}

func TestConfig_InvalidBroker(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("APP_ENV", "development")
	_ = os.Setenv("MESSAGE_BROKER", "unsupported-broker")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error with invalid broker driver, got nil")
	}
}

func TestConfig_Production_MissingKeys(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("APP_ENV", "production")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error in production when keys are missing, got nil")
	}
}

func TestConfig_Production_WithKeys(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("APP_ENV", "production")
	_ = os.Setenv("JWT_SIGNING_KEY", "super-secret-production-signing-key-12345")
	_ = os.Setenv("ENCRYPTION_KEY", "super-secret-production-encryption-key-12345")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error with production keys set: %v", err)
	}

	if cfg.JWTSigningKey != "super-secret-production-signing-key-12345" {
		t.Errorf("JWT signing key mismatch")
	}
	if cfg.PprofEnabled {
		t.Errorf("expected PprofEnabled false in production by default")
	}
}

func TestConfig_DatabaseSelection_Postgres(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("APP_ENV", "development")
	_ = os.Setenv("DB_DRIVER", "PostgreSQL")
	_ = os.Setenv("DATABASE_URL", "postgres://user:pass@localhost:5432/testdb?sslmode=disable")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error loading postgres config: %v", err)
	}
	if cfg.DBDriver != "postgres" {
		t.Errorf("expected DBDriver postgres, got %q", cfg.DBDriver)
	}
	if cfg.DatabaseURL != "postgres://user:pass@localhost:5432/testdb?sslmode=disable" {
		t.Errorf("expected DatabaseURL match, got %q", cfg.DatabaseURL)
	}
}

func TestConfig_DatabaseSelection_MySQL(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("APP_ENV", "development")
	_ = os.Setenv("DATABASE_DRIVER", "MySQL")
	_ = os.Setenv("DATABASE_URL", "mysql://root:secret@127.0.0.1:3306/struct_dev")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error loading mysql config: %v", err)
	}
	if cfg.DBDriver != "mysql" {
		t.Errorf("expected DBDriver mysql, got %q", cfg.DBDriver)
	}
	if cfg.DatabaseURL != "mysql://root:secret@127.0.0.1:3306/struct_dev" {
		t.Errorf("expected DatabaseURL match, got %q", cfg.DatabaseURL)
	}
}

func TestConfig_DatabaseSelection_AutoDetect(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("APP_ENV", "development")
	_ = os.Setenv("DATABASE_URL", "postgres://pguser:pgpass@db.internal:5432/app")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error auto-detecting postgres: %v", err)
	}
	if cfg.DBDriver != "postgres" {
		t.Errorf("expected auto-detected DBDriver postgres, got %q", cfg.DBDriver)
	}
}

func TestConfig_DatabaseSelection_ComponentAssembly(t *testing.T) {
	os.Clearenv()
	_ = os.Setenv("APP_ENV", "development")
	_ = os.Setenv("DB_DRIVER", "postgres")
	_ = os.Setenv("DB_HOST", "127.0.0.1")
	_ = os.Setenv("DB_PORT", "5432")
	_ = os.Setenv("DB_USER", "custom_user")
	_ = os.Setenv("DB_PASSWORD", "custom_pwd")
	_ = os.Setenv("DB_NAME", "invoices_db")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error assembling DSN: %v", err)
	}
	expected := "postgres://custom_user:custom_pwd@127.0.0.1:5432/invoices_db?sslmode=disable"
	if cfg.DatabaseURL != expected {
		t.Errorf("expected assembled URL %q, got %q", expected, cfg.DatabaseURL)
	}
}
