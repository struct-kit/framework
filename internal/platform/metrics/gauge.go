package metrics

import "sync"

// Gauge is a value that can go up or down — in-flight request counts,
// queue depth, pool saturation.
type Gauge struct {
	mu   sync.Mutex
	name string
	help string
	val  float64
}

func (g *Gauge) Set(v float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.val = v
}

func (g *Gauge) Inc() { g.Add(1) }
func (g *Gauge) Dec() { g.Add(-1) }

func (g *Gauge) Add(delta float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.val += delta
}

func (g *Gauge) value() float64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.val
}
