package middleware

import (
	"net/http"

	"struct-framework/internal/platform/http/appctx"
	"struct-framework/internal/platform/tracing"
)

// Tracing starts one span per request — a child of an incoming
// traceparent header if one is present and valid, a new trace root
// otherwise — and exports it once the response completes. It sets the
// response's own traceparent header too, so a caller can correlate its
// logs with this request's trace.
//
// This imports internal/platform/tracing directly, unlike TokenVerifier/
// Pinger/LocaleResolver's local-interface pattern: tracing is a generic,
// dependency-free platform package, so platform-to-platform here doesn't
// create the kind of coupling those interfaces exist to avoid (avoiding
// a hard dependency on one specific dialect/implementation). Span's
// SetAttribute/SetStatusCode/End are also awkward to express as a
// one-method interface without losing most of the type's point.
//
// Deliberately outermost in the chain: the span's duration should
// reflect true end-to-end request time, including every other
// middleware's own overhead (framework guide §13).
func Tracing(exporter tracing.SpanExporter) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if tc, ok := tracing.ParseTraceParent(r.Header.Get("traceparent")); ok {
				ctx = tracing.WithTraceContext(ctx, tc)
			}

			ctx, span := tracing.StartSpan(ctx, r.Method+" "+r.URL.Path)
			ctx = appctx.WithTrace(ctx, span.TraceID, span.SpanID)
			r = r.WithContext(ctx)

			outgoing := tracing.TraceContext{TraceID: span.TraceID, SpanID: span.SpanID, Sampled: true}
			w.Header().Set("traceparent", outgoing.String())

			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)

			span.SetStatusCode(sw.status)
			span.End()
			_ = exporter.Export(r.Context(), span)
		})
	}
}
