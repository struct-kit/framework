package middleware

import (
	"context"
	"net/http"
	"strings"

	"struct-framework/internal/platform/http/appctx"
)

const authUserIDKey contextKey = "auth_user_id"

// TokenVerifier is the one method Auth needs. Declared here — not
// imported from internal/platform/security/authn — so this package
// never depends on a specific token implementation, matching the same
// pattern router.go's Pinger interface uses for the database.
type TokenVerifier interface {
	VerifyAccessToken(tokenString string) (userID string, err error)
}

// Auth runs as the last step of the middleware chain, ahead of routing.
// If an Authorization: Bearer <token> header is present but the token is
// invalid or expired, Auth rejects the request immediately with 401
// Unauthorized. When a valid token is present, it attaches the authenticated
// user ID to the request context. Unauthenticated requests pass through so
// public routes remain accessible; protected handlers check UserIDFrom and
// return 401 when absent.
func Auth(verifier TokenVerifier) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if token, ok := bearerToken(r); ok {
				userID, err := verifier.VerifyAccessToken(token)
				if err != nil {
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"error":"invalid or expired token"}`))
					return
				}
				ctx := context.WithValue(r.Context(), authUserIDKey, userID)
				ctx = appctx.WithUserID(ctx, userID)
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAuth enforces a valid Bearer token on a route or handler group.
// Unlike Auth (which allows unauthenticated requests to pass through to public routes),
// RequireAuth strictly requires an "Authorization: Bearer <token>" header. If the header
// is missing, malformed, or the token is invalid/expired, it returns 401 Unauthorized immediately.
func RequireAuth(verifier TokenVerifier) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r)
			if !ok {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"authorization header with Bearer token required"}`))
				return
			}
			userID, err := verifier.VerifyAccessToken(token)
			if err != nil {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid or expired token"}`))
				return
			}
			ctx := context.WithValue(r.Context(), authUserIDKey, userID)
			ctx = appctx.WithUserID(ctx, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAuthenticated checks that an authenticated user ID is already present in
// the request context (typically populated upstream by Auth middleware). If absent,
// it responds with 401 Unauthorized immediately.
func RequireAuthenticated() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := UserIDFrom(r.Context()); !ok {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"authentication required"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func bearerToken(r *http.Request) (string, bool) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return "", false
	}
	// Case-insensitive check for "Bearer " prefix
	const prefix = "bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}

// UserIDFrom retrieves the user ID Auth attached to ctx, if any. A
// protected handler that gets ok == false must return 401 itself — Auth
// never does that on a handler's behalf.
func UserIDFrom(ctx context.Context) (string, bool) {
	if id, ok := appctx.UserID(ctx); ok {
		return id, true
	}
	id, ok := ctx.Value(authUserIDKey).(string)
	return id, ok
}
