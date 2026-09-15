package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// COSE_Key labels this package understands (RFC 9053). Positive labels
// decode from CBOR as uint64 in decodeCBORValue; negative labels decode
// as int64 — coseLookup below normalizes that difference.
const (
	coseLabelKty = 1
	coseLabelAlg = 3
	coseLabelCrv = -1
	coseLabelX   = -2
	coseLabelY   = -3

	coseKtyEC2   = 2
	coseAlgES256 = -7
	coseCrvP256  = 1
)

// COSEKey is the small subset of a decoded COSE_Key this package
// supports: an EC2 (elliptic curve) key using the P-256 curve and the
// ES256 algorithm. Anything else is rejected during parsing rather than
// partially represented.
type COSEKey struct {
	KeyType   int64
	Algorithm int64
	Curve     int64
	X, Y      []byte
}

// parseCOSEKey decodes a CBOR-encoded COSE_Key and validates it's an
// EC2/ES256/P-256 key — this package's only supported combination (see
// the package doc comment for why).
func parseCOSEKey(data []byte) (*COSEKey, error) {
	val, _, err := decodeCBORValue(data, 0)
	if err != nil {
		return nil, fmt.Errorf("webauthn: decoding COSE key: %w", err)
	}
	m, ok := val.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("webauthn: COSE key is not a CBOR map")
	}

	kty, err := coseInt(m, coseLabelKty)
	if err != nil {
		return nil, err
	}
	if kty != coseKtyEC2 {
		return nil, fmt.Errorf("webauthn: unsupported COSE key type %d (only EC2 is supported)", kty)
	}

	alg, err := coseInt(m, coseLabelAlg)
	if err != nil {
		return nil, err
	}
	if alg != coseAlgES256 {
		return nil, fmt.Errorf("webauthn: unsupported COSE algorithm %d (only ES256 is supported)", alg)
	}

	crv, err := coseInt(m, coseLabelCrv)
	if err != nil {
		return nil, err
	}
	if crv != coseCrvP256 {
		return nil, fmt.Errorf("webauthn: unsupported COSE curve %d (only P-256 is supported)", crv)
	}

	x, err := coseBytes(m, coseLabelX)
	if err != nil {
		return nil, err
	}
	y, err := coseBytes(m, coseLabelY)
	if err != nil {
		return nil, err
	}

	return &COSEKey{KeyType: kty, Algorithm: alg, Curve: crv, X: x, Y: y}, nil
}

// ECDSAPublicKey reconstructs a usable *ecdsa.PublicKey from the raw
// coordinates, rejecting any point that isn't actually on the P-256
// curve — accepting an off-curve point is a known attack against naive
// elliptic-curve implementations, so this check is load-bearing, not
// defensive filler.
func (k *COSEKey) ECDSAPublicKey() (*ecdsa.PublicKey, error) {
	if len(k.X) != 32 || len(k.Y) != 32 {
		return nil, fmt.Errorf("webauthn: P-256 coordinates must be 32 bytes each (got x=%d, y=%d)", len(k.X), len(k.Y))
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(k.X),
		Y:     new(big.Int).SetBytes(k.Y),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("webauthn: public key point is not on the P-256 curve")
	}
	return pub, nil
}

// coseLookup normalizes the uint64-vs-int64 split decodeCBORValue
// produces for positive vs. negative CBOR integers, so callers can look
// up a COSE label by its signed value regardless of which form it was
// decoded as.
func coseLookup(m map[any]any, label int64) (any, bool) {
	if label >= 0 {
		if v, ok := m[uint64(label)]; ok {
			return v, true
		}
		return nil, false
	}
	v, ok := m[label]
	return v, ok
}

func coseInt(m map[any]any, label int64) (int64, error) {
	v, ok := coseLookup(m, label)
	if !ok {
		return 0, fmt.Errorf("webauthn: COSE key missing label %d", label)
	}
	switch n := v.(type) {
	case uint64:
		return int64(n), nil
	case int64:
		return n, nil
	default:
		return 0, fmt.Errorf("webauthn: COSE key label %d is not an integer", label)
	}
}

func coseBytes(m map[any]any, label int64) ([]byte, error) {
	v, ok := coseLookup(m, label)
	if !ok {
		return nil, fmt.Errorf("webauthn: COSE key missing label %d", label)
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, fmt.Errorf("webauthn: COSE key label %d is not a byte string", label)
	}
	return b, nil
}
