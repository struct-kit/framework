package mysql

import (
	"context"
	"errors"
	"fmt"

	"struct-framework/internal/platform/store"
)

// Migrator applies/rolls back store.Migrations against pool — the MySQL
// counterpart to postgres.Migrator, with the same dirty-flag crash-safety
// discipline, adapted for MySQL's placeholder style (?) and lack of a
// native boolean literal (0/1 instead of Postgres's true/false).
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
			version    VARCHAR(255) PRIMARY KEY,
			dirty      TINYINT(1) NOT NULL DEFAULT 0,
			applied_at DATETIME NULL
		);
	`)
}

func (m *Migrator) checkNotDirty(ctx context.Context) error {
	row := m.pool.QueryRow(ctx, `SELECT version FROM schema_migrations WHERE dirty = 1 ORDER BY version LIMIT 1`)
	var dirtyVersion string
	err := row.Scan(&dirtyVersion)
	if errors.Is(err, store.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("mysql: checking for a dirty migration: %w", err)
	}
	return fmt.Errorf(
		"mysql: migration %s is marked dirty — it failed partway through a previous run "+
			"and must be fixed by hand before migrate up/down can proceed", dirtyVersion)
}

func (m *Migrator) appliedVersions(ctx context.Context) (map[string]bool, error) {
	rows, err := m.pool.Query(ctx, `SELECT version FROM schema_migrations WHERE dirty = 0`)
	if err != nil {
		return nil, fmt.Errorf("mysql: listing applied migrations: %w", err)
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
			`INSERT INTO schema_migrations (version, dirty) VALUES (?, 1)`, mig.Version); err != nil {
			return count, fmt.Errorf("mysql: marking migration %s dirty: %w", mig.Version, err)
		}
		if err := m.pool.ExecScript(ctx, mig.UpSQL); err != nil {
			return count, fmt.Errorf(
				"mysql: migration %s failed and is now marked dirty — fix the underlying "+
					"issue, then repair schema_migrations by hand before retrying: %w", mig.Version, err)
		}
		if _, err := m.pool.Exec(ctx,
			`UPDATE schema_migrations SET dirty = 0, applied_at = NOW() WHERE version = ?`, mig.Version); err != nil {
			return count, fmt.Errorf("mysql: marking migration %s clean: %w", mig.Version, err)
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

	row := m.pool.QueryRow(ctx, `SELECT version FROM schema_migrations WHERE dirty = 0 ORDER BY version DESC LIMIT 1`)
	var version string
	if err := row.Scan(&version); err != nil {
		if errors.Is(err, store.ErrNoRows) {
			return fmt.Errorf("mysql: nothing to roll back")
		}
		return fmt.Errorf("mysql: finding the most recent migration: %w", err)
	}

	var target *store.Migration
	for i := range m.migrations {
		if m.migrations[i].Version == version {
			target = &m.migrations[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("mysql: migration %s is recorded as applied but its files are missing on disk", version)
	}

	if _, err := m.pool.Exec(ctx,
		`UPDATE schema_migrations SET dirty = 1 WHERE version = ?`, version); err != nil {
		return fmt.Errorf("mysql: marking migration %s dirty: %w", version, err)
	}
	if err := m.pool.ExecScript(ctx, target.DownSQL); err != nil {
		return fmt.Errorf(
			"mysql: rolling back migration %s failed and it is now marked dirty — fix the "+
				"underlying issue, then repair schema_migrations by hand before retrying: %w", version, err)
	}
	if _, err := m.pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version = ?`, version); err != nil {
		return fmt.Errorf("mysql: removing migration %s's tracking row: %w", version, err)
	}
	return nil
}
