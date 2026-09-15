package cli

import (
	"context"
	"fmt"
	"time"

	"struct-framework/internal/app/codegen"
	"struct-framework/internal/platform/config"
	"struct-framework/internal/platform/store"
	"struct-framework/internal/platform/store/mysql"
	"struct-framework/internal/platform/store/postgres"
)

func newMigrateCmd() *Command {
	root := &Command{
		Use:   "migrate",
		Short: "Manage database migrations",
	}
	root.AddCommand(
		&Command{
			Use:   "create",
			Short: "Generate a timestamped .up.sql/.down.sql pair under migrations/<dialect>/",
			Run:   runMigrateCreate,
		},
		&Command{
			Use:   "up",
			Short: "Apply all pending migrations against DATABASE_URL",
			Run:   func(args []string) error { return runMigrateDirection("up") },
		},
		&Command{
			Use:   "down",
			Short: "Roll back the most recently applied migration",
			Run:   func(args []string) error { return runMigrateDirection("down") },
		},
		&Command{
			Use:   "status",
			Short: "Display applied and pending migration status",
			Run:   func(args []string) error { return runMigrateStatus() },
		},
	)
	return root
}

// migrationsDirFor returns the dialect-specific migrations directory —
// migrations/postgres or migrations/mysql — since the two dialects need
// genuinely different SQL (column types, boolean literals) even for the
// same logical schema.
func migrationsDirFor(driver string) (string, error) {
	switch driver {
	case "postgres":
		return "migrations/postgres", nil
	case "mysql":
		return "migrations/mysql", nil
	default:
		return "", fmt.Errorf("cli: DB_DRIVER=%q has no migrations directory (memory store has no schema)", driver)
	}
}

func runMigrateCreate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("cli: struct migrate create requires a NAME argument")
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("cli: load config: %w", err)
	}

	var dirs []string
	if cfg.DBDriver == "postgres" || cfg.DBDriver == "mysql" {
		dir, _ := migrationsDirFor(cfg.DBDriver)
		dirs = append(dirs, dir)
	} else {
		// When running with in-memory driver, scaffold for both supported dialects
		dirs = append(dirs, "migrations/postgres", "migrations/mysql")
	}

	name := codegen.Snake(args[0])
	timestamp := time.Now().UTC().Format("20060102150405")

	for _, dir := range dirs {
		upPath := fmt.Sprintf("%s/%s_%s.up.sql", dir, timestamp, name)
		downPath := fmt.Sprintf("%s/%s_%s.down.sql", dir, timestamp, name)

		upContent := fmt.Sprintf("-- %s: write the forward migration here.\n", name)
		downContent := fmt.Sprintf("-- %s: write the rollback for the matching .up.sql here.\n", name)

		if err := codegen.WriteFile(upPath, upContent); err != nil {
			return err
		}
		if err := codegen.WriteFile(downPath, downContent); err != nil {
			return err
		}
		fmt.Println("created", upPath)
		fmt.Println("created", downPath)
	}
	return nil
}

// migrator is the small common surface both dialects' Migrator types
// satisfy — this CLI command doesn't need to know which one it's driving.
type migrator interface {
	Up(ctx context.Context) (int, error)
	Down(ctx context.Context) error
	Status(ctx context.Context) ([]store.MigrationStatus, error)
}

// runMigrateDirection wires `struct migrate up`/`down` to whichever real
// database DB_DRIVER names.
func runMigrateDirection(direction string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("cli: load config: %w", err)
	}

	dir, err := migrationsDirFor(cfg.DBDriver)
	if err != nil {
		return err
	}
	migrations, err := store.LoadMigrations(dir)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var m migrator
	var closeDB func() error

	switch cfg.DBDriver {
	case "postgres":
		pool, err := postgres.Open(cfg.DatabaseURL, 5)
		if err != nil {
			return fmt.Errorf("cli: opening database: %w", err)
		}
		if err := pool.Ping(ctx); err != nil {
			return fmt.Errorf("cli: database unreachable: %w", err)
		}
		m = postgres.NewMigrator(pool, migrations)
		closeDB = pool.Close
	case "mysql":
		pool, err := mysql.Open(cfg.DatabaseURL, 5)
		if err != nil {
			return fmt.Errorf("cli: opening database: %w", err)
		}
		if err := pool.Ping(ctx); err != nil {
			return fmt.Errorf("cli: database unreachable: %w", err)
		}
		m = mysql.NewMigrator(pool, migrations)
		closeDB = pool.Close
	default:
		return fmt.Errorf(
			"cli: `struct migrate %s` needs DB_DRIVER=postgres or DB_DRIVER=mysql — "+
				"the in-memory store has no schema to migrate", direction)
	}
	defer closeDB()

	switch direction {
	case "up":
		count, err := m.Up(ctx)
		if err != nil {
			return err
		}
		if count == 0 {
			fmt.Println("already up to date")
		} else {
			fmt.Printf("applied %d migration(s)\n", count)
		}
		return nil
	case "down":
		if err := m.Down(ctx); err != nil {
			return err
		}
		fmt.Println("rolled back one migration")
		return nil
	default:
		return fmt.Errorf("cli: unknown migrate direction %q", direction)
	}
}

func runMigrateStatus() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("cli: load config: %w", err)
	}

	dir, err := migrationsDirFor(cfg.DBDriver)
	if err != nil {
		return err
	}
	migrations, err := store.LoadMigrations(dir)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var m migrator
	var closeDB func() error

	switch cfg.DBDriver {
	case "postgres":
		pool, err := postgres.Open(cfg.DatabaseURL, 5)
		if err != nil {
			return fmt.Errorf("cli: opening database: %w", err)
		}
		if err := pool.Ping(ctx); err != nil {
			return fmt.Errorf("cli: database unreachable: %w", err)
		}
		m = postgres.NewMigrator(pool, migrations)
		closeDB = pool.Close
	case "mysql":
		pool, err := mysql.Open(cfg.DatabaseURL, 5)
		if err != nil {
			return fmt.Errorf("cli: opening database: %w", err)
		}
		if err := pool.Ping(ctx); err != nil {
			return fmt.Errorf("cli: database unreachable: %w", err)
		}
		m = mysql.NewMigrator(pool, migrations)
		closeDB = pool.Close
	default:
		return fmt.Errorf("cli: `struct migrate status` needs DB_DRIVER=postgres or DB_DRIVER=mysql")
	}
	defer closeDB()

	statuses, err := m.Status(ctx)
	if err != nil {
		return err
	}

	appliedCount := 0
	pendingCount := 0
	for _, s := range statuses {
		tag := "[PENDING]"
		if s.Applied {
			tag = "[APPLIED]"
			appliedCount++
		} else {
			pendingCount++
		}
		fmt.Printf("%s %s_%s\n", tag, s.Version, s.Name)
	}
	fmt.Printf("Total: %d migration(s) (%d applied, %d pending)\n", len(statuses), appliedCount, pendingCount)
	return nil
}
