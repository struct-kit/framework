package tests

import (
	"bytes"
	"strings"
	"testing"

	"struct-framework/internal/platform/metrics"
)

func TestRegistry_Counter(t *testing.T) {
	reg := metrics.NewRegistry()
	c := reg.NewCounter("test_counter_total", "Test counter help")
	c.Inc()
	c.Add(4)

	var buf bytes.Buffer
	n, err := reg.WriteTo(&buf)
	if err != nil {
		t.Fatalf("unexpected WriteTo error: %v", err)
	}
	if n <= 0 || int64(buf.Len()) != n {
		t.Errorf("expected byte count %d, got %d", buf.Len(), n)
	}

	out := buf.String()
	if !strings.Contains(out, "# HELP test_counter_total Test counter help") {
		t.Errorf("missing HELP line in output: %s", out)
	}
	if !strings.Contains(out, "# TYPE test_counter_total counter") {
		t.Errorf("missing TYPE line in output: %s", out)
	}
	if !strings.Contains(out, "test_counter_total 5") {
		t.Errorf("expected counter value 5 in output: %s", out)
	}
}

func TestRegistry_CounterVec(t *testing.T) {
	reg := metrics.NewRegistry()
	cv := reg.NewCounterVec("http_requests_total", "HTTP requests", "method", "status")
	cv.WithLabelValues("GET", "200").Inc()
	cv.WithLabelValues("GET", "200").Inc()
	cv.WithLabelValues("POST", "201").Inc()

	var buf bytes.Buffer
	_, err := reg.WriteTo(&buf)
	if err != nil {
		t.Fatalf("unexpected WriteTo error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `http_requests_total{method="GET",status="200"} 2`) {
		t.Errorf("missing GET 200 metric: %s", out)
	}
	if !strings.Contains(out, `http_requests_total{method="POST",status="201"} 1`) {
		t.Errorf("missing POST 201 metric: %s", out)
	}
}

func TestRegistry_Gauge(t *testing.T) {
	reg := metrics.NewRegistry()
	g := reg.NewGauge("active_connections", "Number of active connections")
	g.Set(10)
	g.Inc()
	g.Dec()

	var buf bytes.Buffer
	_, err := reg.WriteTo(&buf)
	if err != nil {
		t.Fatalf("unexpected WriteTo error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "active_connections 10") {
		t.Errorf("expected gauge value 10: %s", out)
	}
}

func TestRegistry_Histogram(t *testing.T) {
	reg := metrics.NewRegistry()
	h := reg.NewHistogram("request_duration_seconds", "Request latency", []float64{0.01, 0.05, 0.1, 0.5, 1.0})
	h.Observe(0.02)
	h.Observe(0.04)
	h.Observe(0.2)

	var buf bytes.Buffer
	_, err := reg.WriteTo(&buf)
	if err != nil {
		t.Fatalf("unexpected WriteTo error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `request_duration_seconds_bucket{le="0.01"} 0`) {
		t.Errorf("expected bucket le=0.01 count 0: %s", out)
	}
	if !strings.Contains(out, `request_duration_seconds_bucket{le="0.05"} 2`) {
		t.Errorf("expected bucket le=0.05 count 2: %s", out)
	}
	if !strings.Contains(out, `request_duration_seconds_bucket{le="+Inf"} 3`) {
		t.Errorf("expected bucket +Inf count 3: %s", out)
	}
	if !strings.Contains(out, `request_duration_seconds_count 3`) {
		t.Errorf("expected total count 3: %s", out)
	}
}
