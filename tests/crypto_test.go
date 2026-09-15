package tests

import (
	"strings"
	"testing"

	"struct-framework/internal/support/crypto"
)

func TestCrypto_Password_HashAndVerify(t *testing.T) {
	password := "CorrectHorseBatteryStaple123!"
	hash, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("unexpected error hashing password: %v", err)
	}

	if !strings.HasPrefix(hash, "$pbkdf2-sha256$") {
		t.Errorf("expected hash format starting with $pbkdf2-sha256$, got %s", hash)
	}

	match, err := crypto.VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("unexpected error verifying password: %v", err)
	}
	if !match {
		t.Errorf("expected password to match hash")
	}

	matchWrong, err := crypto.VerifyPassword("WrongPassword123!", hash)
	if err != nil {
		t.Fatalf("unexpected error on wrong password verify: %v", err)
	}
	if matchWrong {
		t.Errorf("expected wrong password to fail verification")
	}
}

func TestCrypto_FieldEncryption_Roundtrip(t *testing.T) {
	secretKey := crypto.DeriveKey("my-arbitrary-length-master-secret-phrase")
	if len(secretKey) != 32 {
		t.Fatalf("expected 32-byte derived key, got %d", len(secretKey))
	}

	plaintext := "otpauth://totp/Struct:user@example.com?secret=JBSWY3DPEHPK3PXP"
	encrypted, err := crypto.EncryptField(plaintext, secretKey)
	if err != nil {
		t.Fatalf("unexpected encryption error: %v", err)
	}
	if encrypted == plaintext {
		t.Errorf("ciphertext matches plaintext")
	}

	decrypted, err := crypto.DecryptField(encrypted, secretKey)
	if err != nil {
		t.Fatalf("unexpected decryption error: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("expected %q, got %q", plaintext, decrypted)
	}
}
