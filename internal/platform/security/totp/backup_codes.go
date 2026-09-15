package totp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// GenerateBackupCodes returns n random, human-typeable codes in
// "XXXXX-XXXXX" form (10 hex characters, uppercased). Codes are returned
// to the caller once, in plaintext — only HashBackupCode's digest is
// ever persisted.
func GenerateBackupCodes(n int) ([]string, error) {
	codes := make([]string, n)
	for i := range codes {
		code, err := generateBackupCode()
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

func generateBackupCode() (string, error) {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("totp: generating backup code: %w", err)
	}
	s := strings.ToUpper(hex.EncodeToString(b))
	return s[:5] + "-" + s[5:], nil
}

// HashBackupCode returns the SHA-256 hex digest of a normalized
// (uppercased, trimmed) code, for storage and lookup — never the
// plaintext code itself.
func HashBackupCode(code string) string {
	normalized := strings.ToUpper(strings.TrimSpace(code))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}
