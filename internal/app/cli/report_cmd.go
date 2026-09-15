package cli

import (
	"context"
	"fmt"
	"time"

	"struct-framework/internal/platform/config"
	"struct-framework/internal/platform/store"
	"struct-framework/internal/platform/store/mysql"
	"struct-framework/internal/platform/store/postgres"
	"struct-framework/internal/reports"
)

func newReportCmd() *Command {
	root := &Command{
		Use:   "report",
		Short: "Run an aggregate report",
	}
	root.AddCommand(&Command{
		Use:   "signups",
		Short: "Print daily signup counts for the last 30 days",
		Run:   runSignupReport,
	})
	return root
}

func runSignupReport(args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("cli: load config: %w", err)
	}
	if cfg.DBDriver != "postgres" && cfg.DBDriver != "mysql" {
		return fmt.Errorf("cli: `struct report signups` needs DB_DRIVER=postgres or DB_DRIVER=mysql")
	}

	var db store.Driver
	var closeDB func() error

	dbURL := cfg.DatabaseURL
	if cfg.DatabaseReplicaURL != "" {
		dbURL = cfg.DatabaseReplicaURL
	}

	switch cfg.DBDriver {
	case "postgres":
		pool, err := postgres.Open(dbURL, 2)
		if err != nil {
			return fmt.Errorf("cli: opening database: %w", err)
		}
		db, closeDB = pool, pool.Close
	case "mysql":
		pool, err := mysql.Open(dbURL, 2)
		if err != nil {
			return fmt.Errorf("cli: opening database: %w", err)
		}
		db, closeDB = pool, pool.Close
	}
	defer closeDB()

	if err := pingDB(db); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	counts, err := reports.SignupReport(ctx, db, cfg.DBDriver, 30)
	if err != nil {
		return err
	}
	if len(counts) == 0 {
		fmt.Println("no signups in the last 30 days")
		return nil
	}
	for _, c := range counts {
		fmt.Printf("%s  %d\n", c.Day, c.Count)
	}
	return nil
}
