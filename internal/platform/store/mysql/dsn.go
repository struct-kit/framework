package mysql

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
}

// parseDSN accepts mysql://user:password@host:port/dbname URLs.
// Deviation from convention: go-sql-driver/mysql's traditional DSN format
// is "user:pass@tcp(host:port)/dbname" — this package uses a URL-style
// DSN instead, for consistency with the postgres package and the rest of
// this framework's configuration (DATABASE_URL is a URL everywhere else).
func parseDSN(raw string) (dsn, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return dsn{}, fmt.Errorf("mysql: invalid connection string: %w", err)
	}
	if u.Scheme != "mysql" {
		return dsn{}, fmt.Errorf("mysql: connection string must use mysql://, got %q", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		host = "127.0.0.1"
	}
	port := u.Port()
	if port == "" {
		port = "3306"
	}

	password, _ := u.User.Password()
	database := strings.TrimPrefix(u.Path, "/")
	if database == "" {
		return dsn{}, fmt.Errorf("mysql: connection string is missing a database name")
	}

	return dsn{
		Host:     host,
		Port:     port,
		User:     u.User.Username(),
		Password: password,
		Database: database,
	}, nil
}
