// Package store defines the one contract every repository is written
// against (framework guide §5). PostgreSQL and MySQL implementations
// (internal/platform/store/postgres, internal/platform/store/mysql) each
// satisfy Driver independently — business logic in internal/mvc/services
// never imports either dialect package directly.
package store

import (
	"context"
	"errors"
)

// Driver is satisfied by a connection pool and, within a transaction, by
// the transaction itself — both can Exec/Query/QueryRow identically.
type Driver interface {
	Exec(ctx context.Context, query string, args ...any) (Result, error)
	Query(ctx context.Context, query string, args ...any) (Rows, error)
	QueryRow(ctx context.Context, query string, args ...any) Row
	BeginTx(ctx context.Context) (Tx, error)
	Ping(ctx context.Context) error
	Close() error
}

// Tx is a Driver scoped to one transaction, plus Commit/Rollback. Nested
// transactions are not supported — call BeginTx again inside a Tx and
// implementations return an error rather than silently nesting.
type Tx interface {
	Driver
	Commit() error
	Rollback() error
}

// Result reports how many rows a write statement affected. Not every
// command tag carries a row count (e.g. "BEGIN") — implementations return
// 0 rather than erroring for those.
type Result interface {
	RowsAffected() (int64, error)
}

// Row is a single-row result, as returned by QueryRow. Scan returns
// ErrNoRows if the query matched no row — callers map that to
// apperr.NotFound rather than propagating a driver-specific error.
type Row interface {
	Scan(dest ...any) error
}

// Rows is a multi-row result. Callers must call Next before the first
// Scan, exactly like database/sql.
type Rows interface {
	Row
	Next() bool
	Close() error
}

// ErrNoRows mirrors database/sql.ErrNoRows so repository code can use the
// same idiom regardless of which dialect backs it.
var ErrNoRows = errors.New("store: no rows in result set")
