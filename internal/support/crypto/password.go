// Package crypto provides password hashing built entirely on the standard
// library.
//
// Deviation from the framework guide: §6.3 specifies Argon2id
// (golang.org/x/crypto/argon2). This build environment has no network
// access to the Go module proxy, so PBKDF2-HMAC-SHA256 (RFC 8018) is used
// as a stdlib-only stand-in with a high iteration count. Swap HashPassword/
// VerifyPassword for golang.org/x/crypto/argon2's IDKey as soon as module
// fetching is available — the encoded-string format below is versioned
// (the "pbkdf2-sha256" tag) precisely so both formats can be verified side
// by side during a migration, with new hashes written in the new format
// only.
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

const (
	pbkdf2Iterations = 210_000
	pbkdf2KeyLen     = 32
	saltLen          = 16
	algTag           = "pbkdf2-sha256"
)

// HashPassword derives a salted PBKDF2-HMAC-SHA256 hash of password and
// returns it encoded as "$pbkdf2-sha256$i=<iterations>$<salt>$<hash>",
// base64 (raw, unpadded) for the salt and hash segments.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("crypto: generate salt: %w", err)
	}
	hash := pbkdf2(password, salt, pbkdf2Iterations, pbkdf2KeyLen)
	return fmt.Sprintf("$%s$i=%d$%s$%s",
		algTag,
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword reports whether password matches the encoded hash produced
// by HashPassword, using a constant-time comparison of the derived key.
func VerifyPassword(password, encoded string) (bool, error) {
	salt, iterations, wantHash, err := decode(encoded)
	if err != nil {
		return false, err
	}
	gotHash := pbkdf2(password, salt, iterations, len(wantHash))
	return subtle.ConstantTimeCompare(gotHash, wantHash) == 1, nil
}

// DummyHash returns a fixed, valid-format hash used for timing-safe
// unknown-account handling on login: a lookup for a nonexistent email still
// runs a full VerifyPassword call against this value, so response timing
// cannot be used to distinguish "wrong password" from "no such account".
func DummyHash() string {
	// Precomputed once; the password and salt are arbitrary and never used
	// to authenticate anything real.
	const fixed = "$pbkdf2-sha256$i=210000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	return fixed
}

func decode(encoded string) (salt []byte, iterations int, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	// parts[0] is "" because encoded starts with "$".
	if len(parts) != 5 || parts[1] != algTag {
		return nil, 0, nil, fmt.Errorf("crypto: unrecognized hash format")
	}
	iterField := parts[2]
	if !strings.HasPrefix(iterField, "i=") {
		return nil, 0, nil, fmt.Errorf("crypto: malformed iteration field")
	}
	iterations, err = strconv.Atoi(strings.TrimPrefix(iterField, "i="))
	if err != nil {
		return nil, 0, nil, fmt.Errorf("crypto: malformed iteration count: %w", err)
	}
	salt, err = base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, 0, nil, fmt.Errorf("crypto: malformed salt: %w", err)
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, 0, nil, fmt.Errorf("crypto: malformed hash: %w", err)
	}
	return salt, iterations, hash, nil
}

// pbkdf2 implements RFC 8018 PBKDF2 with HMAC-SHA256 as the pseudorandom
// function. Hand-rolled because this build environment cannot fetch
// golang.org/x/crypto/pbkdf2 either.
func pbkdf2(password string, salt []byte, iterations, keyLen int) []byte {
	prf := func() hmacState { return newHMACState(password) }
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen

	dk := make([]byte, 0, numBlocks*hashLen)
	for block := 1; block <= numBlocks; block++ {
		dk = append(dk, pbkdf2Block(prf, salt, iterations, uint32(block))...)
	}
	return dk[:keyLen]
}

type hmacState struct {
	password string
}

func newHMACState(password string) hmacState { return hmacState{password: password} }

func (h hmacState) sum(data []byte) []byte {
	mac := hmac.New(sha256.New, []byte(h.password))
	mac.Write(data)
	return mac.Sum(nil)
}

func pbkdf2Block(prf func() hmacState, salt []byte, iterations int, blockIndex uint32) []byte {
	state := prf()

	blockNum := []byte{
		byte(blockIndex >> 24),
		byte(blockIndex >> 16),
		byte(blockIndex >> 8),
		byte(blockIndex),
	}

	u := state.sum(append(append([]byte{}, salt...), blockNum...))
	result := append([]byte{}, u...)

	for i := 1; i < iterations; i++ {
		u = state.sum(u)
		for j := range result {
			result[j] ^= u[j]
		}
	}
	return result
}
