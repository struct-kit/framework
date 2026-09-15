package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// DeriveKey normalizes an arbitrary-length secret (ENCRYPTION_KEY, which
// operators may set to any string) into exactly 32 bytes — AES-256's
// required key size — via SHA-256. This is a KDF-free normalization, not
// a password hash: ENCRYPTION_KEY is expected to already be a
// high-entropy secret (e.g. `openssl rand -base64 32`), not a
// human-chosen password.
func DeriveKey(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// EncryptField encrypts plaintext with AES-256-GCM under key (must be 32
// bytes — use DeriveKey) and returns base64(nonce || ciphertext || tag).
// Used for data that must be decrypted later (TOTP secrets) — never for
// passwords, which use one-way hashing (password.go) instead.
func EncryptField(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("crypto: creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("crypto: creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("crypto: generating nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawStdEncoding.EncodeToString(ciphertext), nil
}

// DecryptField reverses EncryptField.
func DecryptField(encoded string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("crypto: creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("crypto: creating GCM: %w", err)
	}

	data, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("crypto: decoding ciphertext: %w", err)
	}
	if len(data) < gcm.NonceSize() {
		return "", fmt.Errorf("crypto: ciphertext shorter than nonce")
	}

	nonce, ct := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("crypto: decryption failed (wrong key, or ciphertext was tampered with): %w", err)
	}
	return string(plaintext), nil
}
