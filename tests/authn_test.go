package tests

import (
	"errors"
	"strings"
	"testing"
	"time"

	"struct-framework/internal/platform/security/authn"
)

func TestJWT_IssueAndVerify(t *testing.T) {
	key := []byte("super-secret-test-key-32byteslong!")
	token, err := authn.IssueJWT("user-123", 15*time.Minute, key)
	if err != nil {
		t.Fatalf("unexpected error issuing JWT: %v", err)
	}

	claims, err := authn.VerifyJWT(token, key)
	if err != nil {
		t.Fatalf("unexpected error verifying valid JWT: %v", err)
	}

	if claims.Subject != "user-123" {
		t.Errorf("expected subject user-123, got %s", claims.Subject)
	}
	if claims.ExpiresAt <= claims.IssuedAt {
		t.Errorf("expected ExpiresAt > IssuedAt")
	}

	verifier := authn.NewVerifier(key)
	sub, err := verifier.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("verifier failed to verify access token: %v", err)
	}
	if sub != "user-123" {
		t.Errorf("expected subject user-123, got %s", sub)
	}
}

func TestJWT_ExpiredToken(t *testing.T) {
	key := []byte("super-secret-test-key-32byteslong!")
	token, err := authn.IssueJWT("user-123", -1*time.Minute, key)
	if err != nil {
		t.Fatalf("unexpected error issuing expired JWT: %v", err)
	}

	_, err = authn.VerifyJWT(token, key)
	if !errors.Is(err, authn.ErrExpiredToken) {
		t.Errorf("expected ErrExpiredToken, got %v", err)
	}
}

func TestJWT_WrongKey(t *testing.T) {
	key1 := []byte("super-secret-test-key-32byteslong1")
	key2 := []byte("super-secret-test-key-32byteslong2")

	token, err := authn.IssueJWT("user-123", 15*time.Minute, key1)
	if err != nil {
		t.Fatalf("unexpected error issuing JWT: %v", err)
	}

	_, err = authn.VerifyJWT(token, key2)
	if !errors.Is(err, authn.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for mismatched key, got %v", err)
	}
}

func TestJWT_TamperedToken(t *testing.T) {
	key := []byte("super-secret-test-key-32byteslong!")
	token, err := authn.IssueJWT("user-123", 15*time.Minute, key)
	if err != nil {
		t.Fatalf("unexpected error issuing JWT: %v", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts in JWT, got %d", len(parts))
	}

	// Tamper with payload
	tampered := parts[0] + ".eyJzdWIiOiJhZG1pbiIsImlhdCI6MTIzLCJleHAiOjk5OTk5OTk5OTl9." + parts[2]
	_, err = authn.VerifyJWT(tampered, key)
	if !errors.Is(err, authn.ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for tampered token, got %v", err)
	}
}

func TestOpaqueToken_GenerateAndHash(t *testing.T) {
	token1, err := authn.NewOpaqueToken()
	if err != nil {
		t.Fatalf("unexpected error generating token: %v", err)
	}
	if token1 == "" {
		t.Fatal("empty token generated")
	}

	token2, err := authn.NewOpaqueToken()
	if err != nil {
		t.Fatalf("unexpected error generating second token: %v", err)
	}
	if token1 == token2 {
		t.Errorf("expected unique tokens, got duplicate: %s", token1)
	}

	hash1 := authn.HashToken(token1)
	hash2 := authn.HashToken(token2)
	if hash1 == hash2 {
		t.Errorf("expected distinct hashes")
	}

	recomputed := authn.HashToken(token1)
	if recomputed != hash1 {
		t.Errorf("hash mismatch on repeated call")
	}
}
