package middleware

import (
	"context"
	"net"
	"net/http"
	"strings"

	"struct-framework/internal/platform/http/appctx"
)

const realIPKey contextKey = "real_ip"

// RealIP resolves the caller's real IP address, preferring the
// X-Forwarded-For header's left-most (client) entry when present.
func RealIP() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := resolveIP(r)
			ctx := context.WithValue(r.Context(), realIPKey, ip)
			ctx = appctx.WithClientIP(ctx, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RealIPFrom(ctx context.Context) string {
	if ip := appctx.ClientIP(ctx); ip != "" {
		return ip
	}
	ip, _ := ctx.Value(realIPKey).(string)
	return ip
}

func resolveIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		candidate := strings.TrimSpace(parts[0])
		if candidate != "" {
			return candidate
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
