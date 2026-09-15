package cli

import (
	"context"
	"fmt"

	"struct-framework/internal/app"
	"struct-framework/internal/platform/config"
)

func newServeCmd() *Command {
	return &Command{
		Use:   "serve",
		Short: "Run the HTTP API (equivalent to cmd/api, useful in dev)",
		Run: func(args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("cli: load config: %w", err)
			}
			a, err := app.Build(cfg)
			if err != nil {
				return fmt.Errorf("cli: build app: %w", err)
			}
			return a.Run(context.Background())
		},
	}
}
