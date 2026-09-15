package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"struct-framework/internal/platform/security/authn"
)

// accessTokenTTL and refreshTokenTTL are shared by both dialects'
// AuthService — defined once here so postgres_auth_service.go and
// mysql_auth_service.go can't drift on session lifetimes.
const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 30 * 24 * time.Hour

	maxLoginAttempts = 5
	lockoutDuration  = 15 * time.Minute
	backupCodeCount  = 10
)

// newFamilyID and newRefreshTokenID both just need a unique random
// string — reusing authn.NewOpaqueToken (32 bytes of crypto/rand, hex
// encoded) is fine for either purpose, and having one shared
// implementation means postgres_auth_service.go and
// mysql_auth_service.go can't drift on how IDs are generated.
func newFamilyID() string {
	id, err := authn.NewOpaqueToken()
	if err != nil {
		// crypto/rand failing is exceptionally unlikely; fall back to a
		// time-based value rather than failing login outright over it.
		return fmt.Sprintf("family-%d", time.Now().UnixNano())
	}
	return id
}

func newRefreshTokenID() (string, error) {
	return authn.NewOpaqueToken()
}

func b64Encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64Decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// fixedWidthBytes returns n's big-endian representation, left-padded
// with zeros to exactly width bytes. big.Int.Bytes() alone omits leading
// zero bytes, which numerically round-trips fine through
// big.Int.SetBytes but makes stored coordinate lengths inconsistent —
// this keeps every stored P-256 coordinate exactly 32 bytes.
func fixedWidthBytes(n *big.Int, width int) []byte {
	b := n.Bytes()
	if len(b) >= width {
		return b
	}
	padded := make([]byte, width)
	copy(padded[width-len(b):], b)
	return padded
}

// reconstructECDSAPublicKey rebuilds the P-256 public key stored by a
// passkey registration from its base64url-encoded coordinates. The
// coordinates were already validated as an on-curve P-256 point once, at
// registration time (webauthn.COSEKey.ECDSAPublicKey) — nothing has
// touched them since, so this reconstruction doesn't repeat that check.
func reconstructECDSAPublicKey(xB64, yB64 string) (*ecdsa.PublicKey, error) {
	x, err := b64Decode(xB64)
	if err != nil {
		return nil, fmt.Errorf("services: decoding stored public key x: %w", err)
	}
	y, err := b64Decode(yB64)
	if err != nil {
		return nil, fmt.Errorf("services: decoding stored public key y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}
