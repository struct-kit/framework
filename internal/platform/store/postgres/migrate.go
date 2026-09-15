package postgres

import (
	"context"
	"errors"
	"fmt"

	"struct-framework/internal/platform/store"
)

// Migrator applies/rolls back store.Migrations against pool, tracked in a
// schema_migrations table with golang-migrate-style dirty-flag
// discipline: a migration is marked dirty before it runs and clean only
// once it succeeds. A dirty row blocks further Up/Down calls until fixed
// by hand — silently retrying a migration that failed partway through
// (DDL is not always transactional) risks re-running statements that
// already took effect.
type Migrator struct {
	pool       *Pool
	migrations []store.Migration
}

func NewMigrator(pool *Pool, migrations []store.Migration) *Migrator {
	return &Migrator{pool: pool, migrations: migrations}
}

func (m *Migrator) ensureTable(ctx context.Context) error {
	return m.pool.ExecScript(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			dirty      BOOLEAN NOT NULL DEFAULT FALSE,
			applied_at TIMESTAMPTZ
		);
	`)
}

func (m *Migrator) checkNotDirty(ctx context.Context) error {
	row := m.pool.QueryRow(ctx, `SELECT version FROM schema_migrations WHERE dirty = true ORDER BY version LIMIT 1`)
	var dirtyVersion string
	err := row.Scan(&dirtyVersion)
	if errors.Is(err, store.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("postgres: checking for a dirty migration: %w", err)
	}
	return fmt.Errorf(
		"postgres: migration %s is marked dirty — it failed partway through a previous run "+
			"and must be fixed by hand before migrate up/down can proceed", dirtyVersion)
}

func (m *Migrator) appliedVersions(ctx context.Context) (map[string]bool, error) {
	rows, err := m.pool.Query(ctx, `SELECT version FROM schema_migrations WHERE dirty = false`)
	if err != nil {
		return nil, fmt.Errorf("postgres: listing applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, nil
}

// Status returns the applied status for every known migration in order.
func (m *Migrator) Status(ctx context.Context) ([]store.MigrationStatus, error) {
	if err := m.ensureTable(ctx); err != nil {
		return nil, err
	}
	applied, err := m.appliedVersions(ctx)
	if err != nil {
		return nil, err
	}
	statuses := make([]store.MigrationStatus, len(m.migrations))
	for i, mig := range m.migrations {
		statuses[i] = store.MigrationStatus{
			Version: mig.Version,
			Name:    mig.Name,
			Applied: applied[mig.Version],
		}
	}
	return statuses, nil
}

// Up applies every migration not yet recorded as applied, in version
// order, stopping at the first failure (leaving that one version dirty).
// It returns how many were applied.
func (m *Migrator) Up(ctx context.Context) (int, error) {
	if err := m.ensureTable(ctx); err != nil {
		return 0, err
	}
	if err := m.checkNotDirty(ctx); err != nil {
		return 0, err
	}
	applied, err := m.appliedVersions(ctx)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, mig := range m.migrations {
		if applied[mig.Version] {
			continue
		}
		if _, err := m.pool.Exec(ctx,
			`INSERT INTO schema_migrations (version, dirty) VALUES ($1, true)`, mig.Version); err != nil {
			return count, fmt.Errorf("postgres: marking migration %s dirty: %w", mig.Version, err)
		}
		if err := m.pool.ExecScript(ctx, mig.UpSQL); err != nil {
			return count, fmt.Errorf(
				"postgres: migration %s failed and is now marked dirty — fix the underlying "+
					"issue, then repair schema_migrations by hand before retrying: %w", mig.Version, err)
		}
		if _, err := m.pool.Exec(ctx,
			`UPDATE schema_migrations SET dirty = false, applied_at = now() WHERE version = $1`, mig.Version); err != nil {
			return count, fmt.Errorf("postgres: marking migration %s clean: %w", mig.Version, err)
		}
		count++
	}
	return count, nil
}

// Down rolls back the single most recently applied migration.
func (m *Migrator) Down(ctx context.Context) error {
	if err := m.ensureTable(ctx); err != nil {
		return err
	}
	if err := m.checkNotDirty(ctx); err != nil {
		return err
	}

	row := m.pool.QueryRow(ctx, `SELECT version FROM schema_migrations WHERE dirty = false ORDER BY version DESC LIMIT 1`)
	var version string
	if err := row.Scan(&version); err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return fmt.Errorf("postgres: nothing to roll back")
		}
		return fmt.Errorf("postgres: finding the most recent migration: %w", err)
	}

	var target *store.Migration
	for i := range m.migrations {
		if m.migrations[i].Version == version {
			target = &m.migrations[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("postgres: migration %s is recorded as applied but its files are missing on disk", version)
	}

	if _, err := m.pool.Exec(ctx,
		`UPDATE schema_migrations SET dirty = true WHERE version = $1`, version); err != nil {
		return fmt.Errorf("postgres: marking migration %s dirty: %w", version, err)
	}
	if err := m.pool.ExecScript(ctx, target.DownSQL); err != nil {
		return fmt.Errorf(
			"postgres: rolling back migration %s failed and it is now marked dirty — fix the "+
				"underlying issue, then repair schema_migrations by hand before retrying: %w", version, err)
	}
	if _, err := m.pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = $1`, version); err != nil {
		return fmt.Errorf("postgres: removing migration %s's tracking row: %w", version, err)
	}
	return nil
}
