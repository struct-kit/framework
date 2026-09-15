// Package tracing implements the framework guide's §12 tracing
// requirement: W3C Trace Context propagation and span timing.
//
// Deviation from the framework guide: §12 specifies the OpenTelemetry
// SDK with an OTLP exporter — not fetchable in this build environment.
// The propagation format itself (the "traceparent" HTTP header) is a
// simple, stable, W3C-standardized *text* format
// (https://www.w3.org/TR/trace-context/), so implementing it carries
// none of the risk a binary wire protocol would. What's NOT implemented:
// tracestate, baggage, and — same as internal/platform/rpc's gRPC gap —
// a real OTLP exporter. LogExporter (exporter.go) is the only exporter
// shipped; wiring a real OTLP/HTTP or OTLP/gRPC exporter is a documented
// follow-up, not attempted here.
package tracing

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

const w3cVersion = "00"

// TraceContext is the W3C traceparent triple: which trace this belongs
// to, which span is "current", and whether it's sampled.
type TraceContext struct {
	TraceID string // 32 lowercase hex characters
	SpanID  string // 16 lowercase hex characters
	Sampled bool
}

// ParseTraceParent parses a traceparent header value. A malformed or
// unsupported-version header returns ok=false — per the W3C spec's own
// guidance, callers should treat that exactly like "no header was
// present" and start a fresh trace, not error out.
func ParseTraceParent(header string) (TraceContext, bool) {
	parts := strings.Split(header, "-")
	if len(parts) != 4 {
		return TraceContext{}, false
	}
	version, traceID, spanID, flags := parts[0], parts[1], parts[2], parts[3]

	if version != w3cVersion {
		return TraceContext{}, false
	}
	if len(traceID) != 32 || len(spanID) != 16 || len(flags) != 2 {
		return TraceContext{}, false
	}
	if !isHex(traceID) || !isHex(spanID) || !isHex(flags) || allZero(traceID) || allZero(spanID) {
		return TraceContext{}, false
	}

	flagByte, err := hex.DecodeString(flags)
	if err != nil {
		return TraceContext{}, false
	}
	return TraceContext{TraceID: traceID, SpanID: spanID, Sampled: flagByte[0]&0x01 != 0}, true
}

// String renders tc as a traceparent header value.
func (tc TraceContext) String() string {
	flags := "00"
	if tc.Sampled {
		flags = "01"
	}
	return fmt.Sprintf("%s-%s-%s-%s", w3cVersion, tc.TraceID, tc.SpanID, flags)
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func allZero(s string) bool {
	for _, c := range s {
		if c != '0' {
			return false
		}
	}
	return true
}

func newTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func newSpanID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
