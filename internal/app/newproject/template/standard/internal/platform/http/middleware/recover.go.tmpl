package middleware

import (
	"log/slog"
	"net/http"
)

// Recover catches any panic in a handler further down the chain, logs it
// with a stack-free summary (the recovered value only — a full stack trace
// goes to the logger's source-line info, not into the response), and
// returns 500 instead of crashing the process.
func Recover(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error("panic recovered",
						"panic", rec,
						"path", r.URL.Path,
						"method", r.Method,
					)
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"error":"internal error"}`))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
