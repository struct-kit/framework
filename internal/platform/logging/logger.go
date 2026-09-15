// Package logging builds the process-wide structured logger: JSON output in
// production, human-readable text in development, with the service name
// and contextual correlation attributes attached to every log record.
package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"struct-framework/internal/platform/config"
	"struct-framework/internal/platform/http/appctx"
)

// sensitiveKeys are field names that must be redacted in logs for privacy and security.
var sensitiveKeys = map[string]bool{
	"password":      true,
	"secret":        true,
	"token":         true,
	"access_token":  true,
	"refresh_token": true,
	"authorization": true,
	"credit_card":   true,
	"cvv":           true,
	"api_key":       true,
}

// sanitizeAttr redacts values for sensitive keys.
func sanitizeAttr(groups []string, a slog.Attr) slog.Attr {
	keyLower := strings.ToLower(a.Key)
	if sensitiveKeys[keyLower] {
		return slog.String(a.Key, "[REDACTED]")
	}
	return a
}

// ContextHandler wraps an inner slog.Handler and automatically enriches records
// with RequestID, TraceID, UserID, and ClientIP from AppContext when present.
type ContextHandler struct {
	inner slog.Handler
}

func (h *ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if ctx != nil {
		rc := appctx.FromContext(ctx)
		if rc.RequestID != "" {
			r.AddAttrs(slog.String("request_id", rc.RequestID))
		}
		if rc.TraceID != "" {
			r.AddAttrs(slog.String("trace_id", rc.TraceID))
		}
		if rc.UserID != "" {
			r.AddAttrs(slog.String("user_id", rc.UserID))
		}
		if rc.ClientIP != "" {
			r.AddAttrs(slog.String("client_ip", rc.ClientIP))
		}
	}
	return h.inner.Handle(ctx, r)
}

func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ContextHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return &ContextHandler{inner: h.inner.WithGroup(name)}
}

// New builds a *slog.Logger configured from cfg. It includes PII sanitization
// and automatic AppContext enrichment.
func New(cfg config.Config) *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level:       level,
		AddSource:   !cfg.IsProduction(),
		ReplaceAttr: sanitizeAttr,
	}

	var baseHandler slog.Handler
	if cfg.IsProduction() {
		baseHandler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		baseHandler = slog.NewTextHandler(os.Stdout, opts)
	}

	contextHandler := &ContextHandler{inner: baseHandler}

	serviceName := cfg.ServiceName
	if serviceName == "" {
		serviceName = cfg.AppName
	}
	if serviceName == "" {
		serviceName = "struct-framework"
	}

	return slog.New(contextHandler).With(
		"service", serviceName,
		"version", cfg.AppVersion,
	)
}
