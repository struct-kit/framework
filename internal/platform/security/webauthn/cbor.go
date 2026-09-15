// Package webauthn is a from-scratch WebAuthn/FIDO2 registration and
// assertion verifier (framework guide §7's known deviation: no network
// access to fetch a CBOR/WebAuthn library in this build environment).
//
// This is, deliberately, the single highest-risk package in the entire
// codebase — more so than the PostgreSQL/MySQL wire-protocol clients. A
// bug in a wire-protocol parser produces wrong data; a bug in signature
// verification here can mean silently accepting a forged credential.
// Every algorithm below is written from specification knowledge and has
// not been run against a real authenticator (hardware key, platform
// authenticator, or software one) in this session — see PLAN.md.
//
// Deliberately scoped down, and documented here rather than silently
// omitted:
//   - Attestation format "none" ONLY. No packed/tpm/android-key/
//     android-safetynet/fido-u2f attestation verification — those
//     validate a vendor trust chain, which is out of scope for a
//     bootstrap implementation. "none" means the credential's public key
//     is trusted on first use (registration must happen over an
//     authenticated, ideally already-logged-in session — which is
//     exactly how this pass wires it in: passkey registration is ✱).
//   - COSE algorithm ES256 (ECDSA P-256 + SHA-256) ONLY. No ES384/ES512/
//     EdDSA/RS256. A credential using any other algorithm is rejected
//     with a clear error, not silently mishandled.
//   - Definite-length CBOR items only — indefinite-length strings/
//     arrays/maps are rejected outright rather than partially parsed.
//   - No extension processing (any WebAuthn extension outputs in
//     authenticatorData are ignored, not validated).
//   - Passkeys are wired in this pass as a second authentication factor
//     only, alongside TOTP — not yet as a passwordless primary
//     credential (that needs a "which user is this?" resolution step
//     this pass doesn't build; see PLAN.md's Pass 4c scope note).
package webauthn

import (
	"encoding/binary"
	"fmt"
)

// decodeCBORValue decodes one CBOR data item starting at data[pos] and
// returns it as one of: uint64 (major type 0), int64 (major type 1,
// negative), []byte (major type 2), string (major type 3), []any (major
// type 4), map[any]any (major type 5, keys are uint64/int64/string), or
// bool/nil (major type 7, simple values). Tags (major type 6) are
// unwrapped transparently — the tag number itself is discarded.
func decodeCBORValue(data []byte, pos int) (value any, next int, err error) {
	majorType, length, pos, err := readCBORHeader(data, pos)
	if err != nil {
		return nil, pos, err
	}

	switch majorType {
	case 0: // unsigned integer
		return length, pos, nil

	case 1: // negative integer: encoded value represents -1-length
		return -1 - int64(length), pos, nil

	case 2: // byte string
		end := pos + int(length)
		if length > uint64(len(data)) || end > len(data) {
			return nil, pos, fmt.Errorf("cbor: truncated byte string")
		}
		return data[pos:end], end, nil

	case 3: // text string
		end := pos + int(length)
		if length > uint64(len(data)) || end > len(data) {
			return nil, pos, fmt.Errorf("cbor: truncated text string")
		}
		return string(data[pos:end]), end, nil

	case 4: // array
		if length > 1<<20 {
			return nil, pos, fmt.Errorf("cbor: array length %d exceeds sanity limit", length)
		}
		arr := make([]any, 0, length)
		p := pos
		for i := uint64(0); i < length; i++ {
			var item any
			item, p, err = decodeCBORValue(data, p)
			if err != nil {
				return nil, pos, err
			}
			arr = append(arr, item)
		}
		return arr, p, nil

	case 5: // map
		if length > 1<<20 {
			return nil, pos, fmt.Errorf("cbor: map length %d exceeds sanity limit", length)
		}
		m := make(map[any]any, length)
		p := pos
		for i := uint64(0); i < length; i++ {
			var k, v any
			k, p, err = decodeCBORValue(data, p)
			if err != nil {
				return nil, pos, err
			}
			v, p, err = decodeCBORValue(data, p)
			if err != nil {
				return nil, pos, err
			}
			m[k] = v
		}
		return m, p, nil

	case 6: // tag — decode and return the tagged value, discarding the tag number itself
		return decodeCBORValue(data, pos)

	case 7: // simple values: only false/true/null are meaningful here
		switch length {
		case 20:
			return false, pos, nil
		case 21:
			return true, pos, nil
		case 22:
			return nil, pos, nil
		default:
			return nil, pos, fmt.Errorf("cbor: unsupported simple value %d", length)
		}

	default:
		return nil, pos, fmt.Errorf("cbor: unsupported major type %d", majorType)
	}
}

// readCBORHeader reads one item's initial byte and any following
// length/value bytes, returning the major type, the decoded
// length-or-value, and the position just past the header.
// Indefinite-length items (additional info 31) are rejected — see this
// package's doc comment.
func readCBORHeader(data []byte, pos int) (majorType byte, value uint64, next int, err error) {
	if pos >= len(data) {
		return 0, 0, pos, fmt.Errorf("cbor: unexpected end of data")
	}
	first := data[pos]
	majorType = first >> 5
	additional := first & 0x1f
	pos++

	switch {
	case additional < 24:
		return majorType, uint64(additional), pos, nil
	case additional == 24:
		if pos+1 > len(data) {
			return 0, 0, pos, fmt.Errorf("cbor: truncated 1-byte length")
		}
		return majorType, uint64(data[pos]), pos + 1, nil
	case additional == 25:
		if pos+2 > len(data) {
			return 0, 0, pos, fmt.Errorf("cbor: truncated 2-byte length")
		}
		return majorType, uint64(binary.BigEndian.Uint16(data[pos : pos+2])), pos + 2, nil
	case additional == 26:
		if pos+4 > len(data) {
			return 0, 0, pos, fmt.Errorf("cbor: truncated 4-byte length")
		}
		return majorType, uint64(binary.BigEndian.Uint32(data[pos : pos+4])), pos + 4, nil
	case additional == 27:
		if pos+8 > len(data) {
			return 0, 0, pos, fmt.Errorf("cbor: truncated 8-byte length")
		}
		return majorType, binary.BigEndian.Uint64(data[pos : pos+8]), pos + 8, nil
	default:
		return 0, 0, pos, fmt.Errorf("cbor: unsupported additional info %d (indefinite-length items are not supported)", additional)
	}
}
