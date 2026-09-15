package tests

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"struct-framework/internal/platform/tracing"
)

func TestOTLPExporter_Export(t *testing.T) {
	var receivedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exporter := tracing.NewOTLPExporter(server.URL, "test-service")

	span := &tracing.Span{
		TraceID:    "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:     "00f067aa0ba902b7",
		ParentID:   "5fb397be34d23b0f",
		Name:       "GET /v1/users",
		StartTime:  time.Now().Add(-10 * time.Millisecond),
		EndTime:    time.Now(),
		StatusCode: 200,
		Attributes: map[string]string{
			"http.method": "GET",
			"http.route":  "/v1/users",
		},
	}

	ctx := context.Background()
	if err := exporter.Export(ctx, span); err != nil {
		t.Fatalf("Export failed: %v", err)
	}

	if len(receivedBody) == 0 {
		t.Fatalf("expected server to receive payload")
	}

	var parsed map[string]any
	if err := json.Unmarshal(receivedBody, &parsed); err != nil {
		t.Fatalf("failed to parse received json: %v", err)
	}

	resourceSpans, ok := parsed["resourceSpans"].([]any)
	if !ok || len(resourceSpans) == 0 {
		t.Fatalf("expected resourceSpans in payload")
	}
}
