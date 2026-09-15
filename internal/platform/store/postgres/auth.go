package postgres

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// hashMD5Password implements Postgres's md5 auth method exactly as
// documented: concat("md5", md5hex(concat(md5hex(concat(password,
// username)), salt))) — password first in the inner hash, and the salt is
// concatenated as raw bytes (not hex text) to the ASCII hex string from
// the inner hash.
func hashMD5Password(user, password string, salt [4]byte) string {
	inner := md5Hex(password + user)
	outer := md5Hex(inner + string(salt[:]))
	return "md5" + outer
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// SCRAM-SHA-256 (RFC 5802 / RFC 7677) — used by PostgreSQL since v10 as
// the default password authentication method (AuthenticationSASL = code
// 10).  Implementation covers only the client side of the exchange:
//
//   client-first                ->  GS2-header + client-first-message-bare
//   server-first                ->  nonce, salt, i (iterations)
//   client-final                ->  (GS2-header-cbind, nonce, proof)
//   server-final                ->  v (verifier / server-signature)
//
// SASLprep is intentionally not applied to the password: PostgreSQL
// accepts the raw UTF-8 bytes on both ends of the wire and the server
// does its own normalization of the stored digest, so skipping it here
// is interoperable for ASCII passwords (the overwhelming case used in
// docker-compose local-dev setups) and avoids pulling in golang.org/x/
// text/secure/precis as a dependency.  If an internationalized password
// is ever used and rejected, the user can fall back to `md5` auth
// (postgres: section "Password Authentication") without the driver
// needing SASLprep to function.
// ---------------------------------------------------------------------------

const (
	scramSHA256     = "SCRAM-SHA-256"
	scramGS2Header  = "n,,"
	scramNonceBytes = 18
)

// scramClientFirst produces the GS2 header + client-first-message-bare
// and returns both the full wire bytes and the "bare" portion (everything
// after the GS2 header) which is needed later for the AuthMessage.
func scramClientFirst() (gs2AndBare string, bare string, err error) {
	var nonce [scramNonceBytes]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", "", fmt.Errorf("postgres: scram: generating nonce: %w", err)
	}
	r := base64.StdEncoding.EncodeToString(nonce[:])
	bare = fmt.Sprintf("n=,r=%s", r)
	return scramGS2Header + bare, bare, nil
}

// scramServerFirst decodes an AuthenticationSASLContinue payload (the
// server-first-message bytes) and returns the extracted nonce (r=...),
// raw salt bytes, and iteration count.
func scramServerFirst(raw []byte) (combinedNonce string, salt []byte, iterations int, err error) {
	msg := string(raw)
	fields := strings.Split(msg, ",")
	if len(fields) < 3 {
		return "", nil, 0, fmt.Errorf("postgres: scram: malformed server-first-message")
	}
	for _, f := range fields {
		if len(f) < 2 {
			continue
		}
		key, val := f[0], f[2:]
		switch key {
		case 'r':
			combinedNonce = val
		case 's':
			salt, err = base64.StdEncoding.DecodeString(val)
			if err != nil {
				return "", nil, 0, fmt.Errorf("postgres: scram: decoding salt: %w", err)
			}
		case 'i':
			if _, err := fmt.Sscanf(val, "%d", &iterations); err != nil {
				return "", nil, 0, fmt.Errorf("postgres: scram: parsing iterations: %w", err)
			}
		}
	}
	if combinedNonce == "" || len(salt) == 0 || iterations <= 0 {
		return "", nil, 0, fmt.Errorf("postgres: scram: missing field in server-first-message")
	}
	return combinedNonce, salt, iterations, nil
}

// scramHi is PBKDF2-HMAC-SHA256 with dkLen = 32 (one digest).  We keep a
// local implementation to avoid pulling in golang.org/x/crypto/pbkdf2 as
// a dependency for a single call.
func scramHi(password []byte, salt []byte, iterations int) []byte {
	h := hmac.New(sha256.New, password)
	h.Write(salt)
	h.Write([]byte{0, 0, 0, 1})
	uPrev := h.Sum(nil)
	out := make([]byte, len(uPrev))
	copy(out, uPrev)
	for i := 2; i <= iterations; i++ {
		cur := hmac.New(sha256.New, password)
		cur.Write(uPrev)
		uCur := cur.Sum(nil)
		for j := range out {
			out[j] ^= uCur[j]
		}
		uPrev = uCur
	}
	return out
}

// scramClientFinal computes the client-final-message (wire bytes to
// send) plus the expected server signature (v), given the client's
// gs2-header, client-first-bare, and the server's first message.
func scramClientFinal(
	gs2 string,
	clientBare string,
	combinedNonce string,
	salt []byte,
	iterations int,
	password string,
) (clientFinalWire string, serverSig []byte, err error) {
	// Channel-binding: we use gs2-cbind-input = base64(GS2 header) since
	// we are NOT performing channel binding (no TLS / no p-bindings
	// negotiated on AuthenticationSASL).  PostgreSQL explicitly accepts
	// this on SCRAM-SHA-256 without binding.
	cbindInput := base64.StdEncoding.EncodeToString([]byte(gs2))
	clientFinalBare := fmt.Sprintf("c=%s,r=%s", cbindInput, combinedNonce)

	// RFC 5802 §3: AuthMessage = client-first-message-bare + "," +
	// server-first-message + "," + client-final-message-without-proof.
	serverFirst := fmt.Sprintf("r=%s,s=%s,i=%d",
		combinedNonce,
		base64.StdEncoding.EncodeToString(salt),
		iterations,
	)
	authMsg := clientBare + "," + serverFirst + "," + clientFinalBare

	normalizedPW := []byte(password) // see header note: no SASLprep

	saltedPassword := scramHi(normalizedPW, salt, iterations)

	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256Sum(clientKey)

	clientSig := hmacSHA256(storedKey, []byte(authMsg))
	proof := xorBytes(clientKey, clientSig)
	proofB64 := base64.StdEncoding.EncodeToString(proof)

	clientFinalWire = clientFinalBare + ",p=" + proofB64

	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	serverSig = hmacSHA256(serverKey, []byte(authMsg))
	return clientFinalWire, serverSig, nil
}

// scramVerifyServerFinal parses the AuthenticationSASLFinal bytes and
// ensures the server signature matches the one we computed locally.
// Matching proves the server also knows (or can derive) SaltedPassword.
func scramVerifyServerFinal(raw []byte, expectedServerSig []byte) error {
	msg := string(raw)
	var serverSigB64 string
	for _, f := range strings.Split(msg, ",") {
		if len(f) >= 2 && f[0] == 'v' {
			serverSigB64 = f[2:]
			break
		}
	}
	if serverSigB64 == "" {
		return fmt.Errorf("postgres: scram: missing server signature (v=)")
	}
	got, err := base64.StdEncoding.DecodeString(serverSigB64)
	if err != nil {
		return fmt.Errorf("postgres: scram: decoding server signature: %w", err)
	}
	if !hmac.Equal(got, expectedServerSig) {
		return fmt.Errorf("postgres: scram: server signature mismatch")
	}
	return nil
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// ---------------------------------------------------------------------------
// PostgreSQL SASL wire helpers.  The frontend uses the PasswordMessage
// ('p') byte for *both* SASL initial-response and SASL response payloads;
// the content format distinguishes them (RFC doc / PG source auth-scram.c):
//
//   SASLInitialResponse -> "SCRAM-SHA-256\0<int32 len><initial-data>"
//   SASLResponse        -> "<client-final-data>"
// ---------------------------------------------------------------------------

func buildSASLInitialResponse(mechanism string, data []byte) []byte {
	var buf []byte
	buf = appendCString(buf, mechanism)
	if len(data) == 0 {
		buf = appendInt32(buf, -1) // no initial response data
		return buf
	}
	buf = appendInt32(buf, int32(len(data)))
	buf = append(buf, data...)
	return buf
}

func buildSASLResponse(data []byte) []byte {
	// SASLResponse has no length prefix — just the raw bytes followed
	// implicitly by message end (the framing length field handles it).
	return data
}

// parseSASLMechanisms extracts the list of SASL mechanisms from the
// body of an AuthenticationSASL (code 10) payload.  Layout:
//
//	int32    10
//	<repeated NUL-terminated C strings>
//	<one final NUL byte to terminate the list>
func parseSASLMechanisms(afterCode10 []byte) ([]string, error) {
	var mechs []string
	pos := 0
	for pos < len(afterCode10) {
		end := indexOfByte(afterCode10[pos:], 0)
		if end < 0 {
			return nil, fmt.Errorf("postgres: scram: malformed AuthenticationSASL list")
		}
		part := string(afterCode10[pos : pos+end])
		pos += end + 1
		if part == "" {
			// Empty string on the wire = end-of-list marker per PG spec.
			break
		}
		mechs = append(mechs, part)
	}
	if len(mechs) == 0 {
		return nil, fmt.Errorf("postgres: scram: server offered no SASL mechanisms")
	}
	return mechs, nil
}

// extractSASLContinueData returns the raw payload bytes of an
// AuthenticationSASLContinue message (code 11) following the int32(11)
// header — i.e. the server-first-message.
func extractSASLContinueData(payload []byte) ([]byte, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("postgres: scram: short SASLContinue")
	}
	if int32(binary.BigEndian.Uint32(payload[0:4])) != 11 {
		return nil, fmt.Errorf("postgres: scram: expected SASLContinue, got code %d", binary.BigEndian.Uint32(payload[0:4]))
	}
	return payload[4:], nil
}

// extractSASLFinalData returns the raw payload bytes of an
// AuthenticationSASLFinal message (code 12) after the int32(12) header.
func extractSASLFinalData(payload []byte) ([]byte, error) {
	if len(payload) < 4 {
		return nil, fmt.Errorf("postgres: scram: short SASLFinal")
	}
	if int32(binary.BigEndian.Uint32(payload[0:4])) != 12 {
		return nil, fmt.Errorf("postgres: scram: expected SASLFinal, got code %d", binary.BigEndian.Uint32(payload[0:4]))
	}
	return payload[4:], nil
}

func indexOfByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
