// Package mysql is a from-scratch MySQL client/server protocol
// implementation (framework guide §7's known deviation: no network access
// to fetch go-sql-driver/mysql in this build environment).
//
// This package carries more residual risk than
// internal/platform/store/postgres, and that's saying something — neither
// has been run against a real server in this session (see PLAN.md), but
// MySQL's binary protocol has more intricate bit-packing than Postgres's
// (a NULL-bitmap with a 2-bit bootstrap offset, DATETIME packed into a
// variable-length structure keyed by its own length prefix). Treat this
// package as the single highest-risk file set in the whole codebase.
//
// Deliberately scoped down, and documented here rather than silently
// omitted:
//   - Authentication: mysql_native_password only. caching_sha2_password
//     — MySQL 8's default — is NOT implemented; connecting to a server
//     that requires it fails with a clear error naming the gap. A server
//     configured with `default_authentication_plugin=mysql_native_password`
//     (or a user explicitly created with that plugin) is required.
//   - No TLS.
//   - Binary protocol (COM_STMT_PREPARE/EXECUTE) for parameter binding —
//     the only safe way to bind a value without string-concatenating SQL
//     (framework guide §5.4) — but only for the small set of column
//     types this package's own migrations use: string/VARCHAR/TEXT,
//     TINY/LONG/LONGLONG integers, and DATETIME/TIMESTAMP. Anything else
//     returns a clear "unsupported column type" error rather than
//     silently misreading bytes.
//   - Single-packet payloads only — no support for a payload spanning
//     multiple 16 MB packets. Fine for CRUD-sized rows, not for large
//     BLOBs.
//   - No connection compression, no multi-factor auth, no LOAD DATA LOCAL.
package mysql

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Client capability flags (a subset — only the ones this package sets or
// checks). Values are from the MySQL protocol's well-known bit
// assignments.
const (
	capLongPassword     uint32 = 0x00000001
	capConnectWithDB    uint32 = 0x00000008
	capProtocol41       uint32 = 0x00000200
	capTransactions     uint32 = 0x00002000
	capSecureConnection uint32 = 0x00008000
	capMultiStatements  uint32 = 0x00010000
	capMultiResults     uint32 = 0x00020000
	capPluginAuth       uint32 = 0x00080000
)

// clientCapabilities is exactly what this driver declares in the
// handshake response — deliberately NOT capDeprecateEOF, so this package
// can rely on real EOF packets terminating column-definition and row
// sequences instead of disambiguating an EOF-shaped OK packet.
func clientCapabilities(withDB bool) uint32 {
	caps := capLongPassword | capProtocol41 | capSecureConnection |
		capPluginAuth | capMultiStatements | capMultiResults | capTransactions
	if withDB {
		caps |= capConnectWithDB
	}
	return caps
}

// Command byte values (the first byte of a command packet's payload).
const (
	comQuery       = 0x03
	comStmtPrepare = 0x16
	comStmtExecute = 0x17
	comStmtClose   = 0x19
	comQuit        = 0x01
)

// Response packet header bytes.
const (
	headerOK  = 0x00
	headerEOF = 0xfe
	headerErr = 0xff
)

// packet is one length-framed MySQL protocol packet: a 3-byte
// little-endian payload length, a 1-byte sequence number, then the
// payload itself.
type packet struct {
	Sequence byte
	Payload  []byte
}

func readPacket(r io.Reader) (packet, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return packet{}, err
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	seq := header[3]
	if length > 0xffffff-1 {
		return packet{}, fmt.Errorf("mysql: packet payload too large (%d bytes) — multi-packet payloads are not supported", length)
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return packet{}, err
		}
	}
	return packet{Sequence: seq, Payload: payload}, nil
}

func writePacket(w io.Writer, seq byte, payload []byte) error {
	if len(payload) > 0xffffff-1 {
		return fmt.Errorf("mysql: outgoing payload too large (%d bytes) — multi-packet payloads are not supported", len(payload))
	}
	var header [4]byte
	header[0] = byte(len(payload))
	header[1] = byte(len(payload) >> 8)
	header[2] = byte(len(payload) >> 16)
	header[3] = seq
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

// --- length-encoded integers and strings, used pervasively ---

// readLenEncInt reads a length-encoded integer starting at payload[pos]
// and returns its value, whether it represented SQL NULL (only meaningful
// in contexts where NULL is legal, e.g. a text-protocol column value),
// and the position just past it.
func readLenEncInt(payload []byte, pos int) (value uint64, isNull bool, next int, err error) {
	if pos >= len(payload) {
		return 0, false, pos, fmt.Errorf("mysql: truncated length-encoded integer")
	}
	first := payload[pos]
	switch {
	case first < 0xfb:
		return uint64(first), false, pos + 1, nil
	case first == 0xfb:
		return 0, true, pos + 1, nil
	case first == 0xfc:
		if pos+3 > len(payload) {
			return 0, false, pos, fmt.Errorf("mysql: truncated 2-byte length-encoded integer")
		}
		return uint64(binary.LittleEndian.Uint16(payload[pos+1 : pos+3])), false, pos + 3, nil
	case first == 0xfd:
		if pos+4 > len(payload) {
			return 0, false, pos, fmt.Errorf("mysql: truncated 3-byte length-encoded integer")
		}
		v := uint64(payload[pos+1]) | uint64(payload[pos+2])<<8 | uint64(payload[pos+3])<<16
		return v, false, pos + 4, nil
	case first == 0xfe:
		if pos+9 > len(payload) {
			return 0, false, pos, fmt.Errorf("mysql: truncated 8-byte length-encoded integer")
		}
		return binary.LittleEndian.Uint64(payload[pos+1 : pos+9]), false, pos + 9, nil
	default:
		return 0, false, pos, fmt.Errorf("mysql: invalid length-encoded integer prefix 0x%x", first)
	}
}

// readLenEncString reads a length-encoded string (a length-encoded
// integer followed by that many bytes) starting at payload[pos].
func readLenEncString(payload []byte, pos int) (value []byte, isNull bool, next int, err error) {
	length, isNull, pos, err := readLenEncInt(payload, pos)
	if err != nil {
		return nil, false, pos, err
	}
	if isNull {
		return nil, true, pos, nil
	}
	end := pos + int(length)
	if end > len(payload) {
		return nil, false, pos, fmt.Errorf("mysql: truncated length-encoded string")
	}
	return payload[pos:end], false, end, nil
}

func appendLenEncInt(buf []byte, v uint64) []byte {
	switch {
	case v < 0xfb:
		return append(buf, byte(v))
	case v <= 0xffff:
		buf = append(buf, 0xfc)
		return binary.LittleEndian.AppendUint16(buf, uint16(v))
	case v <= 0xffffff:
		buf = append(buf, 0xfd)
		return append(buf, byte(v), byte(v>>8), byte(v>>16))
	default:
		buf = append(buf, 0xfe)
		return binary.LittleEndian.AppendUint64(buf, v)
	}
}

func appendLenEncString(buf []byte, s []byte) []byte {
	buf = appendLenEncInt(buf, uint64(len(s)))
	return append(buf, s...)
}

// readNullTerminated reads bytes up to (not including) the next 0x00,
// returning the value and the position just past the terminator.
func readNullTerminated(payload []byte, pos int) (value []byte, next int, err error) {
	for i := pos; i < len(payload); i++ {
		if payload[i] == 0 {
			return payload[pos:i], i + 1, nil
		}
	}
	return nil, pos, fmt.Errorf("mysql: missing NUL terminator")
}

func appendNullTerminated(buf []byte, s string) []byte {
	buf = append(buf, s...)
	return append(buf, 0)
}
