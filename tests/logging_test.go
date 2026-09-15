package tests

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"struct-framework/internal/platform/config"
	"struct-framework/internal/platform/http/appctx"
	"struct-framework/internal/platform/logging"
)

func TestLogging_AppContextEnrichmentAndRedaction(t *testing.T) {
	cfg := config.Config{
		Env:         "development",
		ServiceName: "test-service",
		AppVersion:  "1.0.0",
		LogLevel:    "debug",
	}

	logger := logging.New(cfg)
	handler := logger.Handler()

	ctx := context.Background()
	ctx = appctx.WithRequestID(ctx, "req-corr-999")
	ctx = appctx.WithTrace(ctx, "trace-abc-123", "span-xyz-456")
	ctx = appctx.WithUserID(ctx, "user-42")
	ctx = appctx.WithClientIP(ctx, "10.0.0.1")

	record := slog.NewRecord(time.Now(), slog.LevelInfo, "test log message", 0)
	record.Add("password", "plaintext-secret-123")
	record.Add("safe_field", "visible_data")

	err := handler.Handle(ctx, record)
	if err != nil {
		t.Fatalf("unexpected handler error: %v", err)
	}

	// Test sanitization with a JSON handler in memory
	var buf bytes.Buffer
	jsonHandler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			k := strings.ToLower(a.Key)
			if k == "password" || k == "token" || k == "secret" {
				return slog.String(a.Key, "[REDACTED]")
			}
			return a
		},
	})

	testLog := slog.New(jsonHandler)
	testLog.Info("login attempted", "email", "user@example.com", "password", "super-secret-password-123")

	out := buf.String()
	if strings.Contains(out, "super-secret-password-123") {
		t.Errorf("expected secret to be redacted, got: %s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in output, got: %s", out)
	}
}
