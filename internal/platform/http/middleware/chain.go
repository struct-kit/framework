// Package middleware implements the full HTTP middleware chain described
// in the framework guide (§6.3): panic recovery, request ID, real-IP
// resolution, security headers, rate limiting, CORS, access logging, and
// request timeout.
package middleware

import "net/http"

type Middleware func(http.Handler) http.Handler

// Chain applies middlewares to h in the order given — the first middleware
// listed is the outermost, so it runs first on the way in and last on the
// way out.
func Chain(h http.Handler, middlewares ...Middleware) http.Handler {
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}
