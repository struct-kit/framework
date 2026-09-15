package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Config identifies this relying party. RPID is typically the bare
// domain (e.g. "example.com"); Origin is the full scheme+host the
// browser reports (e.g. "https://example.com").
type Config struct {
	RPID   string
	Origin string
}

// Credential is what registration produces and assertion verifies
// against — the pieces a caller needs to persist and to re-verify future
// logins.
type Credential struct {
	ID        []byte
	PublicKey *ecdsa.PublicKey
	SignCount uint32
}

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func parseClientData(raw []byte) (*clientData, error) {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return nil, fmt.Errorf("webauthn: parsing clientDataJSON: %w", err)
	}
	return &cd, nil
}

func verifyChallenge(challengeB64 string, expected []byte) error {
	got, err := base64.RawURLEncoding.DecodeString(challengeB64)
	if err != nil {
		return fmt.Errorf("webauthn: malformed challenge encoding: %w", err)
	}
	if !bytes.Equal(got, expected) {
		return fmt.Errorf("webauthn: challenge mismatch")
	}
	return nil
}

// VerifyRegistration verifies a WebAuthn registration ceremony
// (navigator.credentials.create()'s response) and returns the new
// credential to persist. It only accepts attestation format "none" and
// COSE algorithm ES256 — see the package doc comment for why.
func VerifyRegistration(cfg Config, expectedChallenge []byte, clientDataJSON, attestationObject []byte) (*Credential, error) {
	cd, err := parseClientData(clientDataJSON)
	if err != nil {
		return nil, err
	}
	if cd.Type != "webauthn.create" {
		return nil, fmt.Errorf("webauthn: unexpected clientData type %q (want \"webauthn.create\")", cd.Type)
	}
	if err := verifyChallenge(cd.Challenge, expectedChallenge); err != nil {
		return nil, err
	}
	if cd.Origin != cfg.Origin {
		return nil, fmt.Errorf("webauthn: origin mismatch: got %q, want %q", cd.Origin, cfg.Origin)
	}

	attVal, _, err := decodeCBORValue(attestationObject, 0)
	if err != nil {
		return nil, fmt.Errorf("webauthn: parsing attestationObject: %w", err)
	}
	attMap, ok := attVal.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("webauthn: attestationObject is not a CBOR map")
	}

	fmtVal, _ := attMap["fmt"].(string)
	if fmtVal != "none" {
		return nil, fmt.Errorf("webauthn: attestation format %q is not supported (only \"none\" is)", fmtVal)
	}
	// attStmt for "none" format is an empty map by spec — nothing to
	// verify about the (absent) attestation statement itself.

	authDataRaw, ok := attMap["authData"].([]byte)
	if !ok {
		return nil, fmt.Errorf("webauthn: attestationObject is missing authData")
	}
	authData, err := parseAuthenticatorData(authDataRaw)
	if err != nil {
		return nil, err
	}

	if err := checkRPIDAndPresence(cfg, authData); err != nil {
		return nil, err
	}
	if len(authData.CredentialID) == 0 || authData.CredentialPublicKeyRaw == nil {
		return nil, fmt.Errorf("webauthn: authenticatorData has no attested credential data")
	}

	coseKey, err := parseCOSEKey(authData.CredentialPublicKeyRaw)
	if err != nil {
		return nil, err
	}
	pubKey, err := coseKey.ECDSAPublicKey()
	if err != nil {
		return nil, err
	}

	return &Credential{ID: authData.CredentialID, PublicKey: pubKey, SignCount: authData.SignCount}, nil
}

// VerifyAssertion verifies a WebAuthn assertion ceremony
// (navigator.credentials.get()'s response) against a previously
// registered credential's stored public key and sign count. On success
// it returns the new sign count the caller should persist.
func VerifyAssertion(
	cfg Config,
	expectedChallenge []byte,
	storedPubKey *ecdsa.PublicKey,
	storedSignCount uint32,
	clientDataJSON, authenticatorDataRaw, signature []byte,
) (newSignCount uint32, err error) {
	cd, err := parseClientData(clientDataJSON)
	if err != nil {
		return 0, err
	}
	if cd.Type != "webauthn.get" {
		return 0, fmt.Errorf("webauthn: unexpected clientData type %q (want \"webauthn.get\")", cd.Type)
	}
	if err := verifyChallenge(cd.Challenge, expectedChallenge); err != nil {
		return 0, err
	}
	if cd.Origin != cfg.Origin {
		return 0, fmt.Errorf("webauthn: origin mismatch: got %q, want %q", cd.Origin, cfg.Origin)
	}

	authData, err := parseAuthenticatorData(authenticatorDataRaw)
	if err != nil {
		return 0, err
	}
	if err := checkRPIDAndPresence(cfg, authData); err != nil {
		return 0, err
	}

	// The signed message is authenticatorData || SHA-256(clientDataJSON)
	// (WebAuthn §7.2 step "Using credentialPublicKey, verify that sig is
	// a valid signature over the binary concatenation of authData and
	// hash"); ES256 verification then hashes that whole message with
	// SHA-256 again before the actual ECDSA check. The signature itself
	// is ASN.1 DER-encoded, which ecdsa.VerifyASN1 (Go 1.19+) consumes
	// directly — no hand-rolled ASN.1 parsing needed here.
	clientDataHash := sha256.Sum256(clientDataJSON)
	signedMessage := make([]byte, 0, len(authenticatorDataRaw)+len(clientDataHash))
	signedMessage = append(signedMessage, authenticatorDataRaw...)
	signedMessage = append(signedMessage, clientDataHash[:]...)
	digest := sha256.Sum256(signedMessage)

	if !ecdsa.VerifyASN1(storedPubKey, digest[:], signature) {
		return 0, fmt.Errorf("webauthn: signature verification failed")
	}

	// Clone detection: a sign count that fails to increase suggests the
	// credential's private key may have been cloned. Authenticators that
	// always report 0 (many synced/platform passkeys never increment a
	// counter) are deliberately exempted from this check — treating
	// "0 == 0" as non-increasing would falsely lock those users out on
	// every single login.
	if storedSignCount != 0 && authData.SignCount != 0 && authData.SignCount <= storedSignCount {
		return 0, fmt.Errorf("webauthn: sign count did not increase — possible cloned authenticator")
	}

	return authData.SignCount, nil
}

func checkRPIDAndPresence(cfg Config, authData *AuthenticatorData) error {
	expectedRPIDHash := sha256.Sum256([]byte(cfg.RPID))
	if !bytes.Equal(authData.RPIDHash, expectedRPIDHash[:]) {
		return fmt.Errorf("webauthn: RP ID hash mismatch")
	}
	if authData.Flags&flagUserPresent == 0 {
		return fmt.Errorf("webauthn: user presence flag not set")
	}
	return nil
}
