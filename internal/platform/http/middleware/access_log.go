package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// AccessLog logs method, path, status, duration, request ID, and real IP
// for every request. It never logs the request or response body, and never
// dumps raw headers — those can carry credentials or PII (framework guide
// §8.2/§8.3: redact by allowlist, not blocklist).
func AccessLog(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)

			logger.Info("http_request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", RequestIDFrom(r.Context()),
				"remote_ip", RealIPFrom(r.Context()),
			)
		})
	}
}
