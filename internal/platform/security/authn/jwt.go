// Package authn implements the framework guide's §7.3 token primitives:
// short-lived JWT access tokens and rotating opaque refresh tokens.
//
// Deviation from the framework guide: no JWT library is fetchable in
// this build environment, so this is a hand-rolled HS256-only
// implementation. It deliberately never reads the "alg" field out of an
// incoming token to decide how to verify it — verification always
// assumes HS256 and simply fails if the header claims anything else.
// This closes the classic "alg: none" / algorithm-confusion class of
// vulnerability outright, rather than needing to defend against it.
package authn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrExpiredToken = errors.New("authn: token has expired")
	ErrInvalidToken = errors.New("authn: invalid token")
)

// Claims is deliberately minimal: just enough to identify who the token
// was issued for and when it expires. Extend it if a real need arises
// (e.g. a token version for global invalidation) rather than
// speculatively.
type Claims struct {
	Subject   string `json:"sub"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// IssueJWT issues an HS256 access token for subject (the user ID),
// expiring after ttl.
func IssueJWT(subject string, ttl time.Duration, signingKey []byte) (string, error) {
	now := time.Now().UTC()
	claims := Claims{
		Subject:   subject,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}
	return signJWT(claims, signingKey)
}

func signJWT(claims Claims, signingKey []byte) (string, error) {
	headerJSON, err := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("authn: encoding header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("authn: encoding claims: %w", err)
	}

	headerEnc := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsEnc := base64.RawURLEncoding.EncodeToString(claimsJSON)
	signingInput := headerEnc + "." + claimsEnc

	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(signingInput))
	sigEnc := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sigEnc, nil
}

// VerifyJWT checks tokenString's signature and expiry and returns its
// claims. The signature comparison uses hmac.Equal, which is already
// constant-time — never swap this for a plain byte-slice equality check.
func VerifyJWT(tokenString string, signingKey []byte) (Claims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return Claims{}, ErrInvalidToken
	}
	headerEnc, claimsEnc, sigEnc := parts[0], parts[1], parts[2]

	headerJSON, err := base64.RawURLEncoding.DecodeString(headerEnc)
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var h jwtHeader
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return Claims{}, ErrInvalidToken
	}
	if h.Alg != "HS256" {
		// Deliberately not ErrInvalidToken: this is a distinct, loggable
		// condition (someone or something is sending non-HS256 tokens),
		// not routine invalid-credentials traffic.
		return Claims{}, fmt.Errorf("authn: unsupported algorithm %q — only HS256 is accepted", h.Alg)
	}

	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(headerEnc + "." + claimsEnc))
	expectedSig := mac.Sum(nil)

	gotSig, err := base64.RawURLEncoding.DecodeString(sigEnc)
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	if !hmac.Equal(gotSig, expectedSig) {
		return Claims{}, ErrInvalidToken
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(claimsEnc)
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return Claims{}, ErrInvalidToken
	}

	if time.Now().UTC().Unix() > claims.ExpiresAt {
		return Claims{}, ErrExpiredToken
	}
	return claims, nil
}

// Verifier adapts VerifyJWT to middleware.TokenVerifier's single-method
// shape, so internal/platform/http/middleware never needs to import this
// package's types directly — just the one method it calls.
type Verifier struct {
	signingKey []byte
}

func NewVerifier(signingKey []byte) *Verifier {
	return &Verifier{signingKey: signingKey}
}

func (v *Verifier) VerifyAccessToken(tokenString string) (string, error) {
	claims, err := VerifyJWT(tokenString, v.signingKey)
	if err != nil {
		return "", err
	}
	return claims.Subject, nil
}

// NewOpaqueToken generates a random refresh token — 32 bytes of
// crypto/rand, hex-encoded. The plaintext is returned to the caller once
// and never stored; only HashToken's digest is persisted.
func NewOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("authn: generating opaque token: %w", err)
	}
	return fmt.Sprintf("%x", b), nil
}

// HashToken returns the SHA-256 hex digest of token, for storage —
// refresh tokens are looked up by this hash, never by the plaintext.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum)
}
