package middleware

import "net/http"

// SecurityHeaders sets the baseline response headers from the framework
// guide's §7.2. TLS itself is expected to terminate at the edge (reverse
// proxy/load balancer) — HSTS here tells browsers to enforce that.
func SecurityHeaders() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
			next.ServeHTTP(w, r)
		})
	}
}
