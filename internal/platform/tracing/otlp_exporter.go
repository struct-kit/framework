package tracing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// OTLPExporter exports completed Spans to an OpenTelemetry collector via
// standard OTLP/HTTP JSON protocol (typically POST /v1/traces).
type OTLPExporter struct {
	endpoint    string
	serviceName string
	client      *http.Client
	headers     map[string]string
}

type OTLPOption func(*OTLPExporter)

func WithOTLPHTTPClient(c *http.Client) OTLPOption {
	return func(e *OTLPExporter) { e.client = c }
}

func WithOTLPHeaders(headers map[string]string) OTLPOption {
	return func(e *OTLPExporter) { e.headers = headers }
}

// NewOTLPExporter builds an OTLP HTTP trace exporter. If endpoint is empty,
// Export acts as a safe no-op.
func NewOTLPExporter(endpoint, serviceName string, opts ...OTLPOption) *OTLPExporter {
	if serviceName == "" {
		serviceName = "struct-framework"
	}
	e := &OTLPExporter{
		endpoint:    endpoint,
		serviceName: serviceName,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		headers: make(map[string]string),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

type otlpValue struct {
	StringValue string `json:"stringValue,omitempty"`
	IntValue    int64  `json:"intValue,omitempty"`
	BoolValue   *bool  `json:"boolValue,omitempty"`
}

type otlpKeyValue struct {
	Key   string    `json:"key"`
	Value otlpValue `json:"value"`
}

type otlpStatus struct {
	Code int `json:"code"`
}

type otlpSpan struct {
	TraceID           string         `json:"traceId"`
	SpanID            string         `json:"spanId"`
	ParentSpanID      string         `json:"parentSpanId,omitempty"`
	Name              string         `json:"name"`
	StartTimeUnixNano string         `json:"startTimeUnixNano"`
	EndTimeUnixNano   string         `json:"endTimeUnixNano"`
	Attributes        []otlpKeyValue `json:"attributes,omitempty"`
	Status            otlpStatus     `json:"status"`
}

type otlpScopeSpans struct {
	Scope struct {
		Name string `json:"name"`
	} `json:"scope"`
	Spans []otlpSpan `json:"spans"`
}

type otlpResourceSpans struct {
	Resource struct {
		Attributes []otlpKeyValue `json:"attributes"`
	} `json:"resource"`
	ScopeSpans []otlpScopeSpans `json:"scopeSpans"`
}

type otlpTracePayload struct {
	ResourceSpans []otlpResourceSpans `json:"resourceSpans"`
}

// Export serializes the Span into the standard OTLP/HTTP JSON format
// and transmits it to the configured collector endpoint.
func (e *OTLPExporter) Export(ctx context.Context, span *Span) error {
	if e == nil || e.endpoint == "" || span == nil {
		return nil
	}

	startNano := strconv.FormatInt(span.StartTime.UnixNano(), 10)
	endTime := span.EndTime
	if endTime.IsZero() {
		endTime = time.Now().UTC()
	}
	endNano := strconv.FormatInt(endTime.UnixNano(), 10)

	var attrs []otlpKeyValue
	for k, v := range span.Attributes {
		attrs = append(attrs, otlpKeyValue{
			Key:   k,
			Value: otlpValue{StringValue: v},
		})
	}

	statusCode := 1 // STATUS_CODE_OK in OTLP
	if span.StatusCode >= 400 {
		statusCode = 2 // STATUS_CODE_ERROR
	}

	oSpan := otlpSpan{
		TraceID:           span.TraceID,
		SpanID:            span.SpanID,
		ParentSpanID:      span.ParentID,
		Name:              span.Name,
		StartTimeUnixNano: startNano,
		EndTimeUnixNano:   endNano,
		Attributes:        attrs,
		Status:            otlpStatus{Code: statusCode},
	}

	payload := otlpTracePayload{
		ResourceSpans: []otlpResourceSpans{
			{
				Resource: struct {
					Attributes []otlpKeyValue `json:"attributes"`
				}{
					Attributes: []otlpKeyValue{
						{Key: "service.name", Value: otlpValue{StringValue: e.serviceName}},
					},
				},
				ScopeSpans: []otlpScopeSpans{
					{
						Scope: struct {
							Name string `json:"name"`
						}{Name: "struct-framework"},
						Spans: []otlpSpan{oSpan},
					},
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("otlp: failed to marshal trace payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("otlp: failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("otlp: export request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("otlp: collector returned non-2xx status: %d", resp.StatusCode)
	}
	return nil
}
