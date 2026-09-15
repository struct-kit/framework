// Package totp implements RFC 6238 (TOTP) on top of RFC 4226 (HOTP),
// using HMAC-SHA1, 6-digit codes, and a 30-second time step — the
// parameters every standard authenticator app (Google Authenticator,
// Authy, 1Password, etc.) assumes when it isn't told otherwise. Base32
// encoding uses the standard library (encoding/base32), so unlike the
// wire-protocol packages, this one leans on stdlib for the fiddliest
// encoding step rather than hand-rolling it.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	digits     = 6
	timeStep   = 30 * time.Second
	secretLen  = 20 // 160 bits — standard for HMAC-SHA1-based TOTP
	driftSteps = 1  // tolerate one 30s step of clock drift, either direction
)

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a new random base32-encoded (no padding) secret
// suitable for both storage (after encryption — see
// internal/support/crypto.EncryptField) and display/QR-code enrollment.
func GenerateSecret() (string, error) {
	b := make([]byte, secretLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("totp: generating secret: %w", err)
	}
	return base32Encoding.EncodeToString(b), nil
}

// Verify checks code against secret, tolerating ±driftSteps time steps
// for clock drift between the authenticator app and this server. The
// comparison is constant-time (crypto/subtle) — never swap it for a
// plain string comparison.
func Verify(secret, code string) (bool, error) {
	code = strings.TrimSpace(code)
	if len(code) != digits {
		return false, nil
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return false, err
	}

	steps := int64(timeStep.Seconds())
	currentCounter := time.Now().UTC().Unix() / steps

	for delta := int64(-driftSteps); delta <= driftSteps; delta++ {
		candidate := hotp(key, uint64(currentCounter+delta))
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return true, nil
		}
	}
	return false, nil
}

// BuildURI builds an otpauth:// URI for QR-code enrollment — scanning it
// with an authenticator app configures the same algorithm/digits/period
// this package itself uses, so generated and verified codes agree.
func BuildURI(secret, issuer, accountName string) string {
	label := fmt.Sprintf("%s:%s", issuer, accountName)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprintf("%d", digits))
	v.Set("period", fmt.Sprintf("%d", int(timeStep.Seconds())))
	return fmt.Sprintf("otpauth://totp/%s?%s", url.PathEscape(label), v.Encode())
}

func decodeSecret(secret string) ([]byte, error) {
	// Tolerant of case and stray whitespace — some QR/manual-entry paths
	// normalize differently, and base32 is case-insensitive by spec.
	normalized := strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32Encoding.DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("totp: invalid secret encoding: %w", err)
	}
	return key, nil
}

// hotp implements RFC 4226's HOTP algorithm: HMAC-SHA1 over the 8-byte
// big-endian counter, then "dynamic truncation" — the offset is the low
// nibble of the hash's last byte, and the 4 bytes at that offset (with
// the top bit of the first masked off) become a 31-bit integer, reduced
// mod 10^digits.
func hotp(key []byte, counter uint64) string {
	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(counterBytes[:])
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	binCode := (uint32(hash[offset]&0x7f) << 24) |
		(uint32(hash[offset+1]) << 16) |
		(uint32(hash[offset+2]) << 8) |
		uint32(hash[offset+3])

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	code := binCode % mod
	return fmt.Sprintf("%0*d", digits, code)
}
