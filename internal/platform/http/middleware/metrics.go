package middleware

import (
	"net/http"
	"time"
)

// RequestMetrics is the one method Metrics needs — declared here, not
// imported from internal/platform/metrics, matching this package's
// pattern for every other cross-cutting dependency (TokenVerifier,
// LocaleResolver).
type RequestMetrics interface {
	ObserveRequest(method, pattern string, status int, duration time.Duration)
}

// Metrics records one observation per request: method, route pattern,
// status, and duration. It reports the matched *route pattern*
// (e.g. "/v1/users/{id}"), not the raw request path — using the raw path
// would create a new metric series per unique ID ever requested, the
// "cardinality explosion" Prometheus users are specifically warned
// against. Learning the pattern requires cooperation from
// platformhttp.BuildMux (see route_pattern.go's doc comment for why a
// plain context.WithValue can't do this alone).
func Metrics(recorder RequestMetrics) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ctx := WithRoutePatternTracking(r.Context())
			r = r.WithContext(ctx)

			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)

			pattern, ok := RoutePatternFrom(ctx)
			if !ok {
				pattern = "unmatched"
			}
			recorder.ObserveRequest(r.Method, pattern, sw.status, time.Since(start))
		})
	}
}
