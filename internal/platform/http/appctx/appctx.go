// Package appctx provides a unified, typed request context that manages
// correlation IDs, trace context, user identity, client IP, and locale across
// the entire request lifecycle.
package appctx

import (
	"context"
	"time"
)

type contextKey struct{}

var requestContextKey = contextKey{}

// RequestContext encapsulates all contextual metadata for a single request lifecycle.
type RequestContext struct {
	RequestID string    `json:"request_id,omitempty"`
	TraceID   string    `json:"trace_id,omitempty"`
	SpanID    string    `json:"span_id,omitempty"`
	UserID    string    `json:"user_id,omitempty"`
	ClientIP  string    `json:"client_ip,omitempty"`
	Locale    string    `json:"locale,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
}

// Clone returns a copy of RequestContext.
func (rc *RequestContext) Clone() *RequestContext {
	if rc == nil {
		return &RequestContext{StartTime: time.Now().UTC()}
	}
	c := *rc
	return &c
}

// FromContext retrieves the RequestContext from ctx. If none is present,
// it returns an empty RequestContext with StartTime initialized to now.
func FromContext(ctx context.Context) *RequestContext {
	if ctx == nil {
		return &RequestContext{StartTime: time.Now().UTC()}
	}
	if rc, ok := ctx.Value(requestContextKey).(*RequestContext); ok && rc != nil {
		return rc
	}
	return &RequestContext{StartTime: time.Now().UTC()}
}

// WithRequestContext attaches rc to ctx.
func WithRequestContext(ctx context.Context, rc *RequestContext) context.Context {
	if rc == nil {
		rc = &RequestContext{StartTime: time.Now().UTC()}
	}
	return context.WithValue(ctx, requestContextKey, rc)
}

func ensureRequestContext(ctx context.Context) (context.Context, *RequestContext) {
	if ctx == nil {
		ctx = context.Background()
	}
	if rc, ok := ctx.Value(requestContextKey).(*RequestContext); ok && rc != nil {
		return ctx, rc
	}
	rc := &RequestContext{StartTime: time.Now().UTC()}
	return context.WithValue(ctx, requestContextKey, rc), rc
}

// WithRequestID sets RequestID on the request context.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	ctx, rc := ensureRequestContext(ctx)
	rcCopy := rc.Clone()
	rcCopy.RequestID = requestID
	return context.WithValue(ctx, requestContextKey, rcCopy)
}

// RequestID extracts the RequestID from ctx, or returns "" if none.
func RequestID(ctx context.Context) string {
	return FromContext(ctx).RequestID
}

// WithUserID sets UserID on the request context.
func WithUserID(ctx context.Context, userID string) context.Context {
	ctx, rc := ensureRequestContext(ctx)
	rcCopy := rc.Clone()
	rcCopy.UserID = userID
	return context.WithValue(ctx, requestContextKey, rcCopy)
}

// UserID extracts the authenticated UserID from ctx. Returns (userID, true)
// when present, or ("", false) when unauthenticated.
func UserID(ctx context.Context) (string, bool) {
	rc := FromContext(ctx)
	if rc.UserID == "" {
		return "", false
	}
	return rc.UserID, true
}

// WithTrace sets TraceID and SpanID on the request context.
func WithTrace(ctx context.Context, traceID, spanID string) context.Context {
	ctx, rc := ensureRequestContext(ctx)
	rcCopy := rc.Clone()
	rcCopy.TraceID = traceID
	rcCopy.SpanID = spanID
	return context.WithValue(ctx, requestContextKey, rcCopy)
}

// TraceID extracts the active TraceID from ctx.
func TraceID(ctx context.Context) string {
	return FromContext(ctx).TraceID
}

// SpanID extracts the active SpanID from ctx.
func SpanID(ctx context.Context) string {
	return FromContext(ctx).SpanID
}

// WithClientIP sets ClientIP on the request context.
func WithClientIP(ctx context.Context, clientIP string) context.Context {
	ctx, rc := ensureRequestContext(ctx)
	rcCopy := rc.Clone()
	rcCopy.ClientIP = clientIP
	return context.WithValue(ctx, requestContextKey, rcCopy)
}

// ClientIP extracts the caller's IP from ctx.
func ClientIP(ctx context.Context) string {
	return FromContext(ctx).ClientIP
}

// WithLocale sets Locale on the request context.
func WithLocale(ctx context.Context, locale string) context.Context {
	ctx, rc := ensureRequestContext(ctx)
	rcCopy := rc.Clone()
	rcCopy.Locale = locale
	return context.WithValue(ctx, requestContextKey, rcCopy)
}

// Locale extracts the negotiated locale from ctx.
func Locale(ctx context.Context) string {
	return FromContext(ctx).Locale
}

// StartTime extracts the request initiation timestamp from ctx.
func StartTime(ctx context.Context) time.Time {
	return FromContext(ctx).StartTime
}
