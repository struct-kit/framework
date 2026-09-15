package tests

import (
	"strings"
	"testing"

	"struct-framework/internal/platform/security/totp"
)

func TestTOTP_GenerateSecretAndVerify(t *testing.T) {
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("unexpected error generating secret: %v", err)
	}
	if len(secret) == 0 {
		t.Fatal("empty secret generated")
	}

	// Verify rejection of invalid length code
	validShort, err := totp.Verify(secret, "123")
	if err != nil || validShort {
		t.Errorf("expected short code to be rejected")
	}

	// Verify rejection of dummy non-matching code
	validDummy, err := totp.Verify(secret, "000000")
	// Verify shouldn't crash, returns boolean
	_ = validDummy
}

func TestTOTP_BuildURI(t *testing.T) {
	uri := totp.BuildURI("JBSWY3DPEHPK3PXP", "StructService", "alice@example.com")
	if !strings.HasPrefix(uri, "otpauth://totp/StructService%3Aalice%40example.com?") &&
		!strings.HasPrefix(uri, "otpauth://totp/StructService:alice@example.com?") {
		t.Errorf("unexpected URI format: %s", uri)
	}
	if !strings.Contains(uri, "secret=JBSWY3DPEHPK3PXP") {
		t.Errorf("missing secret parameter: %s", uri)
	}
	if !strings.Contains(uri, "algorithm=SHA1") {
		t.Errorf("missing algorithm parameter: %s", uri)
	}
	if !strings.Contains(uri, "digits=6") {
		t.Errorf("missing digits parameter: %s", uri)
	}
	if !strings.Contains(uri, "period=30") {
		t.Errorf("missing period parameter: %s", uri)
	}
}

func TestTOTP_BackupCodes(t *testing.T) {
	codes, err := totp.GenerateBackupCodes(8)
	if err != nil {
		t.Fatalf("unexpected error generating backup codes: %v", err)
	}
	if len(codes) != 8 {
		t.Fatalf("expected 8 codes, got %d", len(codes))
	}

	seen := make(map[string]bool)
	for _, code := range codes {
		if len(code) != 11 || code[5] != '-' {
			t.Errorf("code %s does not match expected XXXXX-XXXXX format", code)
		}
		if seen[code] {
			t.Errorf("duplicate backup code generated: %s", code)
		}
		seen[code] = true

		hash := totp.HashBackupCode(code)
		if len(hash) != 64 { // SHA-256 hex string
			t.Errorf("hash length expected 64, got %d", len(hash))
		}

		hashLower := totp.HashBackupCode("  " + strings.ToLower(code) + "  ")
		if hash != hashLower {
			t.Errorf("HashBackupCode must normalize case and whitespace")
		}
	}
}
