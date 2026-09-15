package metrics

import (
	"strconv"
	"time"
)

// HTTPMetrics bundles the two standard request-level metrics (framework
// guide §12: "request counts, latency histograms") and exposes the one
// method middleware.RequestMetrics needs — ObserveRequest — so it can be
// passed directly into platformhttp.BuildHandler.
type HTTPMetrics struct {
	requestsTotal   *CounterVec
	requestDuration *Histogram
}

// NewHTTPMetrics registers the standard request metrics on registry and
// returns a handle for recording observations against them.
func NewHTTPMetrics(registry *Registry) *HTTPMetrics {
	return &HTTPMetrics{
		requestsTotal: registry.NewCounterVec(
			"http_requests_total", "Total HTTP requests, by method, route, and status.",
			"method", "route", "status",
		),
		requestDuration: registry.NewHistogram(
			"http_request_duration_seconds", "HTTP request duration in seconds.", nil,
		),
	}
}

func (m *HTTPMetrics) ObserveRequest(method, pattern string, status int, duration time.Duration) {
	m.requestsTotal.WithLabelValues(method, pattern, strconv.Itoa(status)).Inc()
	m.requestDuration.Observe(duration.Seconds())
}
