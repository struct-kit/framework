package tests

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"struct-framework/internal/platform/http/middleware"
)

func TestMiddleware_Recover(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := middleware.Recover(logger)

	panickingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("database connection exploded")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	m(panickingHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 status on panic, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"error":"internal error"`) {
		t.Errorf("expected json error response, got %s", rec.Body.String())
	}
}

func TestMiddleware_RequestID(t *testing.T) {
	m := middleware.RequestID()

	var extractedID string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		extractedID = middleware.RequestIDFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	m(handler).ServeHTTP(rec, req)

	respID := rec.Header().Get(middleware.RequestIDHeader)
	if respID == "" || extractedID != respID {
		t.Errorf("expected request ID set and in context, got %s", respID)
	}
}

func TestMiddleware_SecurityHeaders(t *testing.T) {
	m := middleware.SecurityHeaders()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	m(handler).ServeHTTP(rec, req)

	h := rec.Header()
	if h.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("missing X-Content-Type-Options: nosniff")
	}
	if h.Get("X-Frame-Options") != "DENY" {
		t.Errorf("missing X-Frame-Options: DENY")
	}
}

func TestMiddleware_CORS(t *testing.T) {
	m := middleware.CORS([]string{"https://app.example.com"})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Allowed origin
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Origin", "https://app.example.com")
	m(handler).ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Errorf("expected Access-Control-Allow-Origin set")
	}
}

func TestMiddleware_RateLimit(t *testing.T) {
	limiter := middleware.NewIPRateLimiter(1)
	m := limiter.Middleware()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	makeReq := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		m(handler).ServeHTTP(rec, req)
		return rec.Code
	}

	if code := makeReq(); code != http.StatusOK {
		t.Errorf("req 1 expected 200, got %d", code)
	}
	if code := makeReq(); code != http.StatusOK {
		t.Errorf("req 2 expected 200, got %d", code)
	}
	if code := makeReq(); code != http.StatusTooManyRequests {
		t.Errorf("req 3 expected 429 Too Many Requests, got %d", code)
	}
}
