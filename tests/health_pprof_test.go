package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"struct-framework/internal/app"
	"struct-framework/internal/platform/config"
	platformhttp "struct-framework/internal/platform/http"
)

type mockPinger struct {
	err error
}

func (m mockPinger) Ping(ctx context.Context) error {
	return m.err
}

func TestHealthz_Detailed(t *testing.T) {
	start := time.Now().Add(-5 * time.Minute)
	handler := platformhttp.DetailedHealthzHandler("my-app", "2.0.0", start)

	req := httptest.NewRequest("GET", "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse json response: %v", err)
	}

	if body["status"] != "ok" || body["app"] != "my-app" || body["version"] != "2.0.0" {
		t.Errorf("unexpected body content: %+v", body)
	}
}

func TestReadyz_Multi(t *testing.T) {
	// Case 1: All healthy
	checks := map[string]platformhttp.Pinger{
		"database": mockPinger{err: nil},
		"broker":   mockPinger{err: nil},
	}
	handler := platformhttp.MultiReadyzHandler(checks)

	req := httptest.NewRequest("GET", "/readyz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	// Case 2: One dependency failing
	degradedChecks := map[string]platformhttp.Pinger{
		"database": mockPinger{err: errors.New("connection refused")},
		"broker":   mockPinger{err: nil},
	}
	degradedHandler := platformhttp.MultiReadyzHandler(degradedChecks)

	rec2 := httptest.NewRecorder()
	degradedHandler.ServeHTTP(rec2, req)

	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 Service Unavailable, got %d", rec2.Code)
	}

	var body map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &body)
	if body["status"] != "unavailable" {
		t.Errorf("expected status unavailable, got %v", body["status"])
	}
}

func TestPprof_RoutesMountedConditionally(t *testing.T) {
	// With PprofEnabled = true
	cfgTrue := config.Config{
		AppName:      "test-app",
		PprofEnabled: true,
	}
	ctrlsTrue := app.Controllers{
		Config: cfgTrue,
	}
	routesTrue := app.Routes(ctrlsTrue)

	foundPprof := false
	for _, rt := range routesTrue {
		if rt.Path == "/debug/pprof/" {
			foundPprof = true
			break
		}
	}
	if !foundPprof {
		t.Errorf("expected /debug/pprof/ route to be mounted when PprofEnabled=true")
	}

	// With PprofEnabled = false
	cfgFalse := config.Config{
		AppName:      "test-app",
		PprofEnabled: false,
	}
	ctrlsFalse := app.Controllers{
		Config: cfgFalse,
	}
	routesFalse := app.Routes(ctrlsFalse)

	for _, rt := range routesFalse {
		if rt.Path == "/debug/pprof/" {
			t.Errorf("did not expect /debug/pprof/ to be mounted when PprofEnabled=false")
		}
	}
}
