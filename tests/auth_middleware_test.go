package tests

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"struct-framework/internal/platform/http/appctx"
	"struct-framework/internal/platform/http/middleware"
)

type mockTokenVerifier struct {
	validToken string
	userID     string
}

func (m *mockTokenVerifier) VerifyAccessToken(token string) (string, error) {
	if token == m.validToken {
		return m.userID, nil
	}
	return "", errors.New("invalid or expired token")
}

func TestAuthMiddleware_BearerHeader(t *testing.T) {
	verifier := &mockTokenVerifier{validToken: "secret-token-123", userID: "usr-42"}
	authMid := middleware.Auth(verifier)

	// Case 1: Unauthenticated request should pass through for public routes
	req := httptest.NewRequest(http.MethodGet, "/public", nil)
	rr := httptest.NewRecorder()
	var seenUserID string
	handler := authMid(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if uid, ok := middleware.UserIDFrom(r.Context()); ok {
			seenUserID = uid
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if seenUserID != "" {
		t.Fatalf("expected empty user ID for unauthenticated request, got %q", seenUserID)
	}

	// Case 2: Valid Bearer token
	req = httptest.NewRequest(http.MethodGet, "/profile", nil)
	req.Header.Set("Authorization", "Bearer secret-token-123")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if seenUserID != "usr-42" {
		t.Fatalf("expected user ID 'usr-42', got %q", seenUserID)
	}

	// Case 3: Case-insensitive "bearer" prefix
	seenUserID = ""
	req = httptest.NewRequest(http.MethodGet, "/profile", nil)
	req.Header.Set("Authorization", "bearer secret-token-123")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}
	if seenUserID != "usr-42" {
		t.Fatalf("expected user ID 'usr-42' with lowercase bearer, got %q", seenUserID)
	}

	// Case 4: Invalid token should be rejected with 401
	req = httptest.NewRequest(http.MethodGet, "/profile", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 for invalid token, got %d", rr.Code)
	}
}

func TestRequireAuthMiddleware(t *testing.T) {
	verifier := &mockTokenVerifier{validToken: "tok-abc", userID: "usr-99"}
	reqAuth := middleware.RequireAuth(verifier)

	// Case 1: Missing Authorization header -> 401
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()
	handler := reqAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on missing auth header, got %d", rr.Code)
	}

	// Case 2: Non-Bearer auth scheme -> 401
	req = httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on non-bearer header, got %d", rr.Code)
	}

	// Case 3: Valid Bearer token -> 200 and AppContext populated
	req = httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer tok-abc")
	rr = httptest.NewRecorder()
	var extractedID string
	handler = reqAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if uid, ok := appctx.UserID(r.Context()); ok {
			extractedID = uid
		}
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on valid bearer token, got %d", rr.Code)
	}
	if extractedID != "usr-99" {
		t.Fatalf("expected AppContext UserID 'usr-99', got %q", extractedID)
	}
}

func TestRequireAuthenticatedMiddleware(t *testing.T) {
	guard := middleware.RequireAuthenticated()

	// Unauthenticated -> 401
	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	rr := httptest.NewRecorder()
	handler := guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}

	// Authenticated via AppContext -> 200
	req = httptest.NewRequest(http.MethodGet, "/secure", nil)
	ctx := appctx.WithUserID(req.Context(), "usr-777")
	req = req.WithContext(ctx)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}
