package metrics

import (
	"sort"
	"strings"
	"sync"
)

// Counter is a simple, unlabeled monotonic counter.
type Counter struct {
	mu    sync.Mutex
	name  string
	help  string
	total float64
}

func (c *Counter) Inc() { c.Add(1) }

func (c *Counter) Add(delta float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.total += delta
}

func (c *Counter) value() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}

// CounterVec is a counter with a fixed set of label names (e.g. "method",
// "status") — WithLabelValues returns the child Counter-like handle for
// one specific combination of label values, matching the real
// Prometheus client's own API shape.
type CounterVec struct {
	mu         sync.Mutex
	name       string
	help       string
	labelNames []string
	children   map[string]*vecChild
}

type vecChild struct {
	labelValues []string
	value       float64
}

// WithLabelValues returns a handle scoped to one label-value combination.
// Pass values in the same order labelNames was declared in — this
// minimal implementation doesn't validate that order or count for you.
func (cv *CounterVec) WithLabelValues(values ...string) *counterVecHandle {
	return &counterVecHandle{vec: cv, values: values}
}

type counterVecHandle struct {
	vec    *CounterVec
	values []string
}

func (h *counterVecHandle) Inc() { h.Add(1) }

func (h *counterVecHandle) Add(delta float64) {
	h.vec.mu.Lock()
	defer h.vec.mu.Unlock()
	key := strings.Join(h.values, "\x1f")
	child, ok := h.vec.children[key]
	if !ok {
		child = &vecChild{labelValues: append([]string{}, h.values...)}
		h.vec.children[key] = child
	}
	child.value += delta
}

func (cv *CounterVec) sortedChildren() []*vecChild {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	keys := make([]string, 0, len(cv.children))
	for k := range cv.children {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	result := make([]*vecChild, len(keys))
	for i, k := range keys {
		result[i] = cv.children[k]
	}
	return result
}
