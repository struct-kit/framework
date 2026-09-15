package postgres

import (
	"fmt"
	"net/url"
	"strings"
)

type dsn struct {
	Host     string
	Port     string
	User     string
	Password string
	Database string
	SSLMode  string
}

// parseDSN accepts postgres://user:password@host:port/dbname?sslmode=...
// URLs — the same format the framework guide's examples use for
// DATABASE_URL.
func parseDSN(raw string) (dsn, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return dsn{}, fmt.Errorf("postgres: invalid connection string: %w", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return dsn{}, fmt.Errorf("postgres: connection string must use postgres:// or postgresql://, got %q", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		host = "127.0.0.1"
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}

	password, _ := u.User.Password()
	database := strings.TrimPrefix(u.Path, "/")
	if database == "" {
		return dsn{}, fmt.Errorf("postgres: connection string is missing a database name")
	}

	sslmode := u.Query().Get("sslmode")
	if sslmode == "" {
		sslmode = "disable"
	}

	return dsn{
		Host:     host,
		Port:     port,
		User:     u.User.Username(),
		Password: password,
		Database: database,
		SSLMode:  sslmode,
	}, nil
}
