package metrics

import "net/http"

// Handler returns the /metrics endpoint's handler. Framework guide §11
// recommends exposing this on an internal-only port, never publicly —
// this package doesn't enforce that itself (this bootstrap slice has one
// listen address, not a separate internal port), so restrict access at
// the network/reverse-proxy layer in any real deployment.
func Handler(registry *Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = registry.WriteTo(w)
	}
}
