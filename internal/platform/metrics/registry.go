// Package metrics implements the framework guide's §12 metrics endpoint:
// a Prometheus-compatible /metrics handler.
//
// Deviation from the framework guide: §12 specifies the real Prometheus
// client library (github.com/prometheus/client_golang), not fetchable in
// this build environment. Unlike the wire-protocol packages elsewhere in
// this codebase, this is a low-risk hand-roll: Prometheus's exposition
// format is a stable, simple, line-oriented *text* format — not a binary
// protocol — so there's no framing, no byte-order, no bit-packing to get
// subtly wrong. What's implemented here (Counter, CounterVec, Gauge,
// Histogram, and a Registry that renders them) covers the common case;
// it does not implement Summary metrics or the OpenMetrics exemplar
// extensions.
package metrics

import (
	"fmt"
	"io"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Registry holds every metric a process exposes.
type Registry struct {
	mu         sync.Mutex
	counters   map[string]*Counter
	counterVec map[string]*CounterVec
	gauges     map[string]*Gauge
	histograms map[string]*Histogram
	collectors []func()
}

func NewRegistry() *Registry {
	return &Registry{
		counters:   make(map[string]*Counter),
		counterVec: make(map[string]*CounterVec),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
		collectors: make([]func(), 0),
	}
}

// RegisterRuntimeMetrics registers Go runtime gauges (goroutines, memory allocations).
func (r *Registry) RegisterRuntimeMetrics() {
	goroutines := r.NewGauge("go_goroutines", "Number of goroutines currently existing")
	allocBytes := r.NewGauge("go_memstats_alloc_bytes", "Number of bytes allocated and still in use")
	sysBytes := r.NewGauge("go_memstats_sys_bytes", "Number of bytes obtained from system")

	r.mu.Lock()
	r.collectors = append(r.collectors, func() {
		goroutines.Set(float64(runtime.NumGoroutine()))
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		allocBytes.Set(float64(m.Alloc))
		sysBytes.Set(float64(m.Sys))
	})
	r.mu.Unlock()
}

func (r *Registry) NewCounter(name, help string) *Counter {
	c := &Counter{name: name, help: help}
	r.mu.Lock()
	r.counters[name] = c
	r.mu.Unlock()
	return c
}

func (r *Registry) NewCounterVec(name, help string, labelNames ...string) *CounterVec {
	cv := &CounterVec{name: name, help: help, labelNames: labelNames, children: make(map[string]*vecChild)}
	r.mu.Lock()
	r.counterVec[name] = cv
	r.mu.Unlock()
	return cv
}

func (r *Registry) NewGauge(name, help string) *Gauge {
	g := &Gauge{name: name, help: help}
	r.mu.Lock()
	r.gauges[name] = g
	r.mu.Unlock()
	return g
}

// DefaultHistogramBuckets covers sub-millisecond to 10-second latencies,
// in seconds — a reasonable default for HTTP request duration.
var DefaultHistogramBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

func (r *Registry) NewHistogram(name, help string, buckets []float64) *Histogram {
	if len(buckets) == 0 {
		buckets = DefaultHistogramBuckets
	}
	sorted := append([]float64{}, buckets...)
	sort.Float64s(sorted)
	h := &Histogram{name: name, help: help, buckets: sorted, counts: make([]uint64, len(sorted))}
	r.mu.Lock()
	r.histograms[name] = h
	r.mu.Unlock()
	return h
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.w.Write(p)
	cw.n += int64(n)
	return n, err
}

var _ io.WriterTo = (*Registry)(nil)

// WriteTo renders every registered metric in Prometheus text exposition
// format. Metric names are sorted for deterministic output.
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, fn := range r.collectors {
		fn()
	}

	cw := &countingWriter{w: w}

	for _, name := range sortedKeys(r.counters) {
		c := r.counters[name]
		if _, err := fmt.Fprintf(cw, "# HELP %s %s\n# TYPE %s counter\n%s %s\n",
			c.name, c.help, c.name, c.name, formatFloat(c.value())); err != nil {
			return cw.n, err
		}
	}

	for _, name := range sortedKeys(r.counterVec) {
		cv := r.counterVec[name]
		if _, err := fmt.Fprintf(cw, "# HELP %s %s\n# TYPE %s counter\n", cv.name, cv.help, cv.name); err != nil {
			return cw.n, err
		}
		for _, child := range cv.sortedChildren() {
			if _, err := fmt.Fprintf(cw, "%s{%s} %s\n", cv.name, formatLabels(cv.labelNames, child.labelValues), formatFloat(child.value)); err != nil {
				return cw.n, err
			}
		}
	}

	for _, name := range sortedKeys(r.gauges) {
		g := r.gauges[name]
		if _, err := fmt.Fprintf(cw, "# HELP %s %s\n# TYPE %s gauge\n%s %s\n",
			g.name, g.help, g.name, g.name, formatFloat(g.value())); err != nil {
			return cw.n, err
		}
	}

	for _, name := range sortedKeys(r.histograms) {
		h := r.histograms[name]
		if err := h.writeTo(cw); err != nil {
			return cw.n, err
		}
	}

	return cw.n, nil
}

// formatFloat renders v the way Prometheus's official client libraries
// do: the shortest decimal (or scientific-notation, for very large/small
// magnitudes) representation that round-trips exactly. The exposition
// format explicitly permits either — see
// https://github.com/prometheus/docs/blob/main/content/docs/instrumenting/exposition_formats.md.
// An earlier version of this function built the string with
// fmt.Sprintf("%f", v) (always exactly 6 decimal places) and trimmed
// trailing zeros by hand. That happens to render correctly for values
// this package's own default histogram buckets use, but it silently
// loses precision for anything needing more than 6 decimal places (a
// custom bucket bound smaller than 1e-6, or certain sums), and it does
// unnecessary work either way: %f always computes and discards 6 digits
// regardless of how many the value actually needs, and fmt.Sprintf's
// format-string parsing and reflection-based dispatch cost more than
// strconv.FormatFloat's direct path. prec=-1 here means "use the fewest
// digits necessary to round-trip exactly" — never more than needed,
// never fewer than correct.
func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func formatLabels(names, values []string) string {
	parts := make([]string, len(names))
	for i := range names {
		v := ""
		if i < len(values) {
			v = values[i]
		}
		parts[i] = fmt.Sprintf("%s=%q", names[i], v)
	}
	return strings.Join(parts, ",")
}

// sortedKeys works for any map keyed by string — Go generics let one
// implementation cover counters/gauges/histograms/vecs without repeating
// the same sort-and-collect loop four times.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
