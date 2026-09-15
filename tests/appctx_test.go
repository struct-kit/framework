package tests

import (
	"context"
	"testing"
	"time"

	"struct-framework/internal/platform/http/appctx"
)

func TestAppContext_Lifecycle(t *testing.T) {
	ctx := context.Background()

	// Initial default empty
	rc := appctx.FromContext(ctx)
	if rc.RequestID != "" || rc.UserID != "" {
		t.Fatalf("expected empty context initially")
	}

	// WithRequestID
	ctx = appctx.WithRequestID(ctx, "req-12345")
	if appctx.RequestID(ctx) != "req-12345" {
		t.Errorf("expected RequestID req-12345, got %s", appctx.RequestID(ctx))
	}

	// WithUserID
	ctx = appctx.WithUserID(ctx, "usr-999")
	uid, ok := appctx.UserID(ctx)
	if !ok || uid != "usr-999" {
		t.Errorf("expected UserID usr-999, got %s (ok=%v)", uid, ok)
	}

	// WithTrace
	ctx = appctx.WithTrace(ctx, "trace-abc", "span-def")
	if appctx.TraceID(ctx) != "trace-abc" {
		t.Errorf("expected TraceID trace-abc, got %s", appctx.TraceID(ctx))
	}
	if appctx.SpanID(ctx) != "span-def" {
		t.Errorf("expected SpanID span-def, got %s", appctx.SpanID(ctx))
	}

	// WithClientIP
	ctx = appctx.WithClientIP(ctx, "192.168.1.100")
	if appctx.ClientIP(ctx) != "192.168.1.100" {
		t.Errorf("expected ClientIP 192.168.1.100, got %s", appctx.ClientIP(ctx))
	}

	// WithLocale
	ctx = appctx.WithLocale(ctx, "es")
	if appctx.Locale(ctx) != "es" {
		t.Errorf("expected Locale es, got %s", appctx.Locale(ctx))
	}

	// Verify all values retained in FromContext
	full := appctx.FromContext(ctx)
	if full.RequestID != "req-12345" || full.UserID != "usr-999" || full.TraceID != "trace-abc" || full.ClientIP != "192.168.1.100" || full.Locale != "es" {
		t.Errorf("unexpected full context state: %+v", full)
	}
}

func TestAppContext_Clone(t *testing.T) {
	rc := &appctx.RequestContext{
		RequestID: "req-1",
		UserID:    "user-1",
		StartTime: time.Now().UTC(),
	}

	cloned := rc.Clone()
	if cloned.RequestID != rc.RequestID || cloned.UserID != rc.UserID {
		t.Errorf("clone failed")
	}

	cloned.RequestID = "req-2"
	if rc.RequestID == "req-2" {
		t.Errorf("mutation leaked to original")
	}
}
