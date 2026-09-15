package http

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"struct-framework/internal/platform/config"
	"struct-framework/internal/platform/http/middleware"
	"struct-framework/internal/platform/tracing"
)

// Pinger is the one method /readyz needs from a database or dependency connection.
type Pinger interface {
	Ping(ctx context.Context) error
}

// TokenVerifier is the one method Auth needs.
type TokenVerifier interface {
	VerifyAccessToken(tokenString string) (userID string, err error)
}

// LocaleResolver is the one method Locale needs.
type LocaleResolver interface {
	IsSupported(locale string) bool
}

// Route is one entry in a declarative route table.
type Route struct {
	Method  string
	Path    string
	Handler http.HandlerFunc
}

// BuildMux registers every route on a fresh *http.ServeMux.
func BuildMux(routes []Route) *http.ServeMux {
	mux := http.NewServeMux()
	for _, rt := range routes {
		pattern := rt.Path
		handler := rt.Handler
		mux.HandleFunc(rt.Method+" "+rt.Path, func(w http.ResponseWriter, r *http.Request) {
			middleware.SetRoutePattern(r.Context(), pattern)
			handler(w, r)
		})
	}
	return mux
}

// BuildHandler wraps handler in the full middleware chain.
func BuildHandler(cfg config.Config, logger *slog.Logger, handler http.Handler, verifier TokenVerifier, localeResolver LocaleResolver, requestMetrics middleware.RequestMetrics, spanExporter tracing.SpanExporter) http.Handler {
	limiter := middleware.NewIPRateLimiter(cfg.RateLimitRPS)

	return middleware.Chain(handler,
		middleware.Tracing(spanExporter),
		middleware.Recover(logger),
		middleware.RequestID(),
		middleware.RealIP(),
		middleware.SecurityHeaders(),
		limiter.Middleware(),
		middleware.CORS(nil),
		middleware.Locale(localeResolver, cfg.DefaultLocale),
		middleware.AccessLog(logger),
		middleware.Metrics(requestMetrics),
		middleware.Timeout(10*time.Second),
		middleware.Auth(verifier),
	)
}

// HealthzHandler always returns 200 — process-liveness only.
func HealthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// DetailedHealthzHandler returns a liveness handler containing app metadata and uptime.
func DetailedHealthzHandler(appName, version string, startTime time.Time) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		uptime := time.Since(startTime).Truncate(time.Second).String()
		if uptime == "0s" {
			uptime = "<1s"
		}
		resp := fmt.Sprintf(`{"status":"ok","app":%q,"version":%q,"uptime":%q}`, appName, version, uptime)
		_, _ = w.Write([]byte(resp))
	}
}

// ReadyzHandler returns /readyz's handler for a single DB pinger.
func ReadyzHandler(db Pinger) http.HandlerFunc {
	return MultiReadyzHandler(map[string]Pinger{"database": db})
}

// MultiReadyzHandler checks multiple dependencies (database, message broker, etc.)
// and returns 200 OK if all pass or 503 Service Unavailable if any fails.
func MultiReadyzHandler(checks map[string]Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		allHealthy := true
		statusMap := make(map[string]string)

		for name, pinger := range checks {
			if pinger == nil {
				statusMap[name] = "ready"
				continue
			}
			if err := pinger.Ping(ctx); err != nil {
				allHealthy = false
				statusMap[name] = "unavailable"
			} else {
				statusMap[name] = "healthy"
			}
		}

		status := "ready"
		httpCode := http.StatusOK
		if !allHealthy {
			status = "unavailable"
			httpCode = http.StatusServiceUnavailable
		}

		w.WriteHeader(httpCode)
		payload := map[string]any{
			"status": status,
			"checks": statusMap,
		}
		resp, _ := json.Marshal(payload)
		_, _ = w.Write(resp)
	}
}
