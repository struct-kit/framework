package metrics

import (
	"fmt"
	"io"
	"math"
	"sync"
)

// Histogram tracks the distribution of observed values (typically
// request durations, in seconds) across a fixed set of upper-bound
// buckets. Bucket counts are cumulative — each bucket counts every
// observation less-than-or-equal to its upper bound, matching
// Prometheus's own histogram convention (the "le" — less-or-equal —
// label in the exposition format).
type Histogram struct {
	mu      sync.Mutex
	name    string
	help    string
	buckets []float64 // ascending upper bounds
	counts  []uint64  // counts[i] = observations <= buckets[i]
	sum     float64
	total   uint64
}

func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += v
	h.total++
	for i, upper := range h.buckets {
		if v <= upper {
			h.counts[i]++
		}
	}
}

func (h *Histogram) writeTo(w io.Writer) error {
	h.mu.Lock()
	buckets := append([]float64{}, h.buckets...)
	counts := append([]uint64{}, h.counts...)
	sum := h.sum
	total := h.total
	name, help := h.name, h.help
	h.mu.Unlock()

	if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", name, help, name); err != nil {
		return err
	}
	for i, upper := range buckets {
		if _, err := fmt.Fprintf(w, "%s_bucket{le=%q} %d\n", name, formatBucketBound(upper), counts[i]); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", name, total); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s_sum %s\n", name, formatFloat(sum)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s_count %d\n", name, total); err != nil {
		return err
	}
	return nil
}

func formatBucketBound(v float64) string {
	if math.IsInf(v, 1) {
		return "+Inf"
	}
	return formatFloat(v)
}
