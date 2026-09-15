// Package postgres is a from-scratch PostgreSQL frontend/backend wire
// protocol v3.0 client (framework guide §7's known deviation: no network
// access to fetch pgx in this build environment).
//
// Deliberately scoped down, and documented here rather than silently
// omitted:
//   - Authentication: cleartext and MD5 only. SCRAM-SHA-256 (Postgres's
//     default since v10) is NOT implemented — connecting to a server
//     configured for scram-sha-256 auth will fail with a clear error
//     naming the gap. This is the single biggest limitation of this
//     package; closing it is the top of Pass 3's follow-up list.
//   - No TLS. connect() refuses any sslmode other than "disable" rather
//     than silently connecting in plaintext when the caller asked for
//     encryption.
//   - Extended query protocol only, text format for both parameters and
//     results — no binary format, no server-side prepared-statement
//     reuse across calls (Parse/Bind/Execute/Sync happen fresh every
//     time, using the unnamed statement and portal).
//   - No LISTEN/NOTIFY, no COPY, no SASLprep.
//
// None of this has been run against a real PostgreSQL server in this
// session — see PLAN.md for why (no Go toolchain, no network access).
// Every message layout below is written from the protocol specification;
// treat this package as the highest-risk, least-verified part of the
// whole codebase until it's been exercised against a live server.
package postgres

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Frontend (client -> server) message type bytes.
const (
	msgPassword  = 'p'
	msgQuery     = 'Q'
	msgParse     = 'P'
	msgBind      = 'B'
	msgExecute   = 'E'
	msgSync      = 'S'
	msgTerminate = 'X'
)

// Backend (server -> client) message type bytes. Several of these share a
// numeric value with a frontend constant above (e.g. 'S' is both frontend
// Sync and backend ParameterStatus) — that's correct: each direction's
// stream only ever carries messages from one role, so the byte's meaning
// is unambiguous in context even though Go can't express that in the type
// system. Distinct constant names keep call sites unambiguous instead.
const (
	msgAuth               = 'R'
	msgParameterStatus    = 'S'
	msgBackendKeyData     = 'K'
	msgReadyForQuery      = 'Z'
	msgErrorResponse      = 'E'
	msgNoticeResponse     = 'N'
	msgRowDescription     = 'T'
	msgDataRow            = 'D'
	msgCommandComplete    = 'C'
	msgParseComplete      = '1'
	msgBindComplete       = '2'
	msgNoData             = 'n'
	msgEmptyQueryResponse = 'I'
)

type rawMessage struct {
	Type    byte
	Payload []byte
}

// readMessage reads one backend message: a 1-byte type, a 4-byte
// big-endian length (which counts itself but not the type byte), and
// then (length-4) bytes of payload.
func readMessage(r io.Reader) (rawMessage, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return rawMessage{}, err
	}
	typ := header[0]
	length := int32(binary.BigEndian.Uint32(header[1:5]))
	payloadLen := length - 4
	if payloadLen < 0 {
		return rawMessage{}, fmt.Errorf("postgres: invalid message length %d for type %q", length, typ)
	}
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return rawMessage{}, err
		}
	}
	return rawMessage{Type: typ, Payload: payload}, nil
}

// writeMessage writes one frontend message: type byte, then a 4-byte
// big-endian length (payload length + 4, since the length field counts
// itself), then the payload.
func writeMessage(w io.Writer, typ byte, payload []byte) error {
	var header [5]byte
	header[0] = typ
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)+4))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

// writeStartupMessage writes the one message with no leading type byte:
// a 4-byte length, the protocol version (3.0 = 196608), then each
// key/value pair as two C strings, terminated by a final zero byte.
func writeStartupMessage(w io.Writer, params map[string]string) error {
	var payload []byte
	payload = appendInt32(payload, 196608) // (major=3 << 16) | minor=0
	for k, v := range params {
		payload = appendCString(payload, k)
		payload = appendCString(payload, v)
	}
	payload = append(payload, 0)

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)+4))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func appendCString(buf []byte, s string) []byte {
	buf = append(buf, s...)
	return append(buf, 0)
}

func appendInt16(buf []byte, v int16) []byte {
	return append(buf, byte(v>>8), byte(v))
}

func appendInt32(buf []byte, v int32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// decodeCString reads a message payload that is entirely one C string
// (e.g. CommandComplete's tag), stopping at the first NUL byte.
func decodeCString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}
