package cli

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"struct-framework/internal/platform/config"
	"struct-framework/internal/platform/events"
	"struct-framework/internal/platform/logging"
	"struct-framework/internal/platform/store"
	"struct-framework/internal/platform/store/mysql"
	"struct-framework/internal/platform/store/postgres"
)

func newRelayCmd() *Command {
	return &Command{
		Use: "relay",
		Short: "Run the outbox relay: poll undispatched events and hand them to a Sink " +
			"(LogSink by default — see internal/platform/events' doc comment on wiring a real broker)",
		Run: runRelay,
	}
}

func runRelay(args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("cli: load config: %w", err)
	}
	if cfg.DBDriver != "postgres" && cfg.DBDriver != "mysql" {
		return fmt.Errorf("cli: `struct relay` needs DB_DRIVER=postgres or DB_DRIVER=mysql — the outbox table lives in a real database")
	}

	logger := logging.New(cfg)

	source, closeDB, err := buildOutboxSource(cfg)
	if err != nil {
		return err
	}
	defer closeDB()

	relay := events.NewRelay(source, events.LogSink{Logger: logger}, logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("outbox relay starting", "db_driver", cfg.DBDriver, "poll_interval", "2s")
	relay.Run(ctx, 2*time.Second)
	logger.Info("outbox relay stopped")
	return nil
}

func buildOutboxSource(cfg config.Config) (events.OutboxSource, func() error, error) {
	noopClose := func() error { return nil }
	switch cfg.DBDriver {
	case "postgres":
		pool, err := postgres.Open(cfg.DatabaseURL, 5)
		if err != nil {
			return nil, noopClose, fmt.Errorf("cli: opening database: %w", err)
		}
		if err := pingDB(pool); err != nil {
			_ = pool.Close()
			return nil, noopClose, err
		}
		return postgres.NewOutboxPublisher(pool), pool.Close, nil
	case "mysql":
		pool, err := mysql.Open(cfg.DatabaseURL, 5)
		if err != nil {
			return nil, noopClose, fmt.Errorf("cli: opening database: %w", err)
		}
		if err := pingDB(pool); err != nil {
			_ = pool.Close()
			return nil, noopClose, err
		}
		return mysql.NewOutboxPublisher(pool), pool.Close, nil
	default:
		return nil, noopClose, fmt.Errorf("cli: unsupported DB_DRIVER %q", cfg.DBDriver)
	}
}

func pingDB(db store.Driver) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.Ping(ctx); err != nil {
		return fmt.Errorf("cli: database unreachable: %w", err)
	}
	return nil
}
