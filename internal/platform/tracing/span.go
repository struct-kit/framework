package tracing

import (
	"context"
	"time"
)

// Span represents one traced operation. Attributes are a small,
// unstructured key-value bag — this package doesn't implement OTel's
// full semantic conventions, just enough structure to be useful.
type Span struct {
	TraceID    string
	SpanID     string
	ParentID   string
	Name       string
	StartTime  time.Time
	EndTime    time.Time
	Attributes map[string]string
	StatusCode int
}

func (s *Span) SetAttribute(key, value string) {
	if s.Attributes == nil {
		s.Attributes = make(map[string]string)
	}
	s.Attributes[key] = value
}

func (s *Span) SetStatusCode(code int) { s.StatusCode = code }

func (s *Span) Duration() time.Duration {
	if s.EndTime.IsZero() {
		return time.Since(s.StartTime)
	}
	return s.EndTime.Sub(s.StartTime)
}

// End marks the span complete. Call exactly once, typically via defer
// right after StartSpan.
func (s *Span) End() {
	if s.EndTime.IsZero() {
		s.EndTime = time.Now().UTC()
	}
}

type spanContextKey struct{}
type traceContextKey struct{}

// WithTraceContext seeds ctx with an incoming trace (typically parsed
// from a request's traceparent header) so the next StartSpan call
// becomes a child of it rather than starting a brand new trace.
func WithTraceContext(ctx context.Context, tc TraceContext) context.Context {
	return context.WithValue(ctx, traceContextKey{}, tc)
}

func TraceContextFromContext(ctx context.Context) (TraceContext, bool) {
	tc, ok := ctx.Value(traceContextKey{}).(TraceContext)
	return tc, ok
}

// StartSpan starts a new span as a child of whichever span (or seeded
// TraceContext) is already present in ctx, or as a new trace root
// otherwise. The returned context carries the new span — retrieve it
// later with SpanFromContext.
func StartSpan(ctx context.Context, name string) (context.Context, *Span) {
	traceID := newTraceID()
	parentID := ""

	if parent, ok := SpanFromContext(ctx); ok {
		traceID = parent.TraceID
		parentID = parent.SpanID
	} else if tc, ok := TraceContextFromContext(ctx); ok {
		traceID = tc.TraceID
		parentID = tc.SpanID
	}

	span := &Span{
		TraceID:   traceID,
		SpanID:    newSpanID(),
		ParentID:  parentID,
		Name:      name,
		StartTime: time.Now().UTC(),
	}
	return context.WithValue(ctx, spanContextKey{}, span), span
}

func SpanFromContext(ctx context.Context) (*Span, bool) {
	span, ok := ctx.Value(spanContextKey{}).(*Span)
	return span, ok
}
