package webauthn

import (
	"encoding/binary"
	"fmt"
)

// authenticatorData flag bits (WebAuthn §6.1).
const (
	flagUserPresent   = 0x01
	flagUserVerified  = 0x04
	flagAttestedData  = 0x40
	flagExtensionData = 0x80
)

// AuthenticatorData is authData's fixed 37-byte header plus, only when
// flagAttestedData is set (registration, never assertion), the variable-
// length attested credential data that follows it.
type AuthenticatorData struct {
	RPIDHash               []byte // 32 bytes
	Flags                  byte
	SignCount              uint32
	AAGUID                 []byte // 16 bytes, only set if attested data is present
	CredentialID           []byte // only set if attested data is present
	CredentialPublicKeyRaw []byte // raw CBOR bytes of the COSE key, only set if attested data is present
}

// parseAuthenticatorData decodes authData exactly as far as this package
// needs to: the fixed header, then — if present — the AAGUID, credential
// ID, and credential public key. Any extension data that follows is
// ignored (see the package doc comment); this function doesn't need to
// consume every byte of data to succeed.
func parseAuthenticatorData(data []byte) (*AuthenticatorData, error) {
	const headerLen = 32 + 1 + 4
	if len(data) < headerLen {
		return nil, fmt.Errorf("webauthn: authenticatorData is shorter than the fixed header (%d bytes)", headerLen)
	}

	ad := &AuthenticatorData{
		RPIDHash:  data[0:32],
		Flags:     data[32],
		SignCount: binary.BigEndian.Uint32(data[33:37]),
	}

	if ad.Flags&flagAttestedData == 0 {
		return ad, nil
	}

	pos := headerLen
	if pos+16+2 > len(data) {
		return nil, fmt.Errorf("webauthn: truncated attested credential data (aaguid/id-length)")
	}
	ad.AAGUID = data[pos : pos+16]
	pos += 16

	credIDLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+credIDLen > len(data) {
		return nil, fmt.Errorf("webauthn: truncated credential id")
	}
	ad.CredentialID = data[pos : pos+credIDLen]
	pos += credIDLen

	// The credential public key is one CBOR item, of whatever length
	// its own encoding specifies. Decode it once here just to find where
	// it ends, and keep the raw bytes for parseCOSEKey to decode
	// properly — simpler and safer than threading a partial decode's
	// internal state back out of decodeCBORValue for this one caller.
	_, next, err := decodeCBORValue(data, pos)
	if err != nil {
		return nil, fmt.Errorf("webauthn: parsing credential public key: %w", err)
	}
	ad.CredentialPublicKeyRaw = data[pos:next]

	return ad, nil
}
