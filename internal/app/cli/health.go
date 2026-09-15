package cli

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func newHealthCmd() *Command {
	return &Command{
		Use:   "health",
		Short: "Hit this instance's own /readyz — also the Docker HEALTHCHECK command",
		Run: func(args []string) error {
			port := os.Getenv("PORT")
			if port == "" {
				port = "8080"
			}
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Get("http://127.0.0.1:" + port + "/readyz")
			if err != nil {
				return fmt.Errorf("health check failed: %w", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("health check returned status %d", resp.StatusCode)
			}
			fmt.Println("ok")
			return nil
		},
	}
}
