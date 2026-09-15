package tracing

import (
	"context"
	"log/slog"
)

// SpanExporter is where a completed Span goes — the seam a real OTLP
// exporter would plug into (see this package's doc comment for why
// none exists here). LogExporter is the only one shipped: enough to
// prove the tracing plumbing works, not a production destination.
type SpanExporter interface {
	Export(ctx context.Context, span *Span) error
}

type LogExporter struct {
	Logger *slog.Logger
}

func (e LogExporter) Export(ctx context.Context, span *Span) error {
	e.Logger.Info("span_completed",
		"trace_id", span.TraceID,
		"span_id", span.SpanID,
		"parent_id", span.ParentID,
		"name", span.Name,
		"duration_ms", span.Duration().Milliseconds(),
		"status_code", span.StatusCode,
	)
	return nil
}
