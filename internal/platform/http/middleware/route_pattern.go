package middleware

import "context"

const routePatternHolderKey contextKey = "route_pattern_holder"

// routePatternHolder is deliberately a pointer stored once in context,
// then mutated later — not a new value re-attached via context.WithValue
// each time. That distinction matters here: Metrics (an outer
// middleware) needs to learn which route pattern matched only after the
// inner mux has already dispatched to a specific handler, i.e. only
// after next.ServeHTTP has returned. A context value set further down
// the chain via context.WithValue never becomes visible to code further
// up once control returns — contexts carry values forward, not
// backward. A shared mutable holder, set up once by the outer layer and
// written into by the inner one, is what actually lets the value cross
// back "up" the call stack.
type routePatternHolder struct {
	pattern string
}

// WithRoutePatternTracking attaches a fresh, empty holder to ctx — called
// once per request, by Metrics, before the mux has had a chance to
// dispatch anywhere.
func WithRoutePatternTracking(ctx context.Context) context.Context {
	return context.WithValue(ctx, routePatternHolderKey, &routePatternHolder{})
}

// SetRoutePattern records pattern into whatever holder is already
// attached to ctx — called by platformhttp.BuildMux's per-route wrapper
// at the moment a route actually matches. A no-op if no holder is
// present (e.g. Metrics wasn't wired into the chain).
func SetRoutePattern(ctx context.Context, pattern string) {
	if holder, ok := ctx.Value(routePatternHolderKey).(*routePatternHolder); ok {
		holder.pattern = pattern
	}
}

// RoutePatternFrom reads back whatever pattern was recorded against
// ctx's holder, if any — call this after the handler chain has returned,
// using the same context WithRoutePatternTracking was applied to.
func RoutePatternFrom(ctx context.Context) (string, bool) {
	holder, ok := ctx.Value(routePatternHolderKey).(*routePatternHolder)
	if !ok || holder.pattern == "" {
		return "", false
	}
	return holder.pattern, true
}
