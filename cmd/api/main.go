package main

import (
	"context"
	"fmt"
	"os"

	"struct-framework/internal/app"
	"struct-framework/internal/platform/config"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	a, err := app.Build(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "startup error:", err)
		os.Exit(1)
	}

	if err := a.Run(context.Background()); err != nil {
		a.Logger.Error("server exited with error", "error", err)
		os.Exit(1)
	}
}
