package middleware

import (
	"net/http"
	"time"
)

// Timeout bounds every request to d using the standard library's own
// http.TimeoutHandler, which returns 503 with a JSON-safe body if the
// handler doesn't finish in time — it does not leak the goroutine running
// the original handler, but that handler must still respect ctx
// cancellation to actually stop doing work.
func Timeout(d time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.TimeoutHandler(next, d, `{"error":"request timed out"}`)
	}
}
