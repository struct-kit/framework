package mysql

import (
	"encoding/binary"
	"fmt"
)

type serverHandshake struct {
	Capabilities   uint32
	AuthPluginData []byte // the full scramble, part 1 + part 2 concatenated
	AuthPluginName string
}

// parseInitialHandshake decodes the server's HandshakeV10 packet — the
// very first packet on a new connection, before the client sends
// anything.
func parseInitialHandshake(payload []byte) (serverHandshake, error) {
	pos := 0
	if len(payload) < 1 {
		return serverHandshake{}, fmt.Errorf("mysql: empty handshake packet")
	}
	protocolVersion := payload[pos]
	pos++
	if protocolVersion != 10 {
		return serverHandshake{}, fmt.Errorf("mysql: unsupported protocol version %d (want 10)", protocolVersion)
	}

	_, pos, err := readNullTerminated(payload, pos) // server version string, unused
	if err != nil {
		return serverHandshake{}, fmt.Errorf("mysql: reading server version: %w", err)
	}

	if pos+4 > len(payload) {
		return serverHandshake{}, fmt.Errorf("mysql: truncated handshake (connection id)")
	}
	pos += 4 // connection id, unused

	if pos+8 > len(payload) {
		return serverHandshake{}, fmt.Errorf("mysql: truncated handshake (auth-plugin-data-part-1)")
	}
	authPart1 := append([]byte{}, payload[pos:pos+8]...)
	pos += 8

	pos++ // filler byte

	if pos+2 > len(payload) {
		return serverHandshake{}, fmt.Errorf("mysql: truncated handshake (capability flags lower)")
	}
	capLower := uint32(binary.LittleEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	if pos+1 > len(payload) {
		return serverHandshake{}, fmt.Errorf("mysql: truncated handshake (character set)")
	}
	pos++ // character set, unused

	if pos+2 > len(payload) {
		return serverHandshake{}, fmt.Errorf("mysql: truncated handshake (status flags)")
	}
	pos += 2 // status flags, unused

	if pos+2 > len(payload) {
		return serverHandshake{}, fmt.Errorf("mysql: truncated handshake (capability flags upper)")
	}
	capUpper := uint32(binary.LittleEndian.Uint16(payload[pos : pos+2]))
	pos += 2
	capabilities := capLower | (capUpper << 16)

	if pos+1 > len(payload) {
		return serverHandshake{}, fmt.Errorf("mysql: truncated handshake (auth-plugin-data length)")
	}
	authPluginDataLen := int(payload[pos])
	pos++

	if pos+10 > len(payload) {
		return serverHandshake{}, fmt.Errorf("mysql: truncated handshake (reserved bytes)")
	}
	pos += 10 // reserved

	part2Len := authPluginDataLen - 8
	if part2Len < 13 {
		part2Len = 13
	}
	if pos+part2Len > len(payload) {
		return serverHandshake{}, fmt.Errorf("mysql: truncated handshake (auth-plugin-data-part-2)")
	}
	authPart2 := payload[pos : pos+part2Len]
	pos += part2Len

	// authPart2's last byte is a NUL terminator, not scramble data.
	scramble := append(authPart1, trimTrailingNUL(authPart2)...)

	authPluginName := ""
	if capabilities&capPluginAuth != 0 && pos < len(payload) {
		name, _, err := readNullTerminated(payload, pos)
		if err == nil {
			authPluginName = string(name)
		}
		// A missing/malformed terminator here isn't fatal — some servers
		// send the plugin name without one as the packet's final bytes.
	}

	return serverHandshake{
		Capabilities:   capabilities,
		AuthPluginData: scramble,
		AuthPluginName: authPluginName,
	}, nil
}

func trimTrailingNUL(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == 0 {
		return b[:len(b)-1]
	}
	return b
}

// buildHandshakeResponse builds the client's HandshakeResponse41 packet.
func buildHandshakeResponse(caps uint32, user, database string, authResponse []byte) []byte {
	var buf []byte
	buf = binary.LittleEndian.AppendUint32(buf, caps)
	buf = binary.LittleEndian.AppendUint32(buf, 1<<24-1) // max packet size
	buf = append(buf, 45)                                // character set: utf8mb4_general_ci
	buf = append(buf, make([]byte, 23)...)               // reserved
	buf = appendNullTerminated(buf, user)

	// CLIENT_SECURE_CONNECTION (always set by clientCapabilities): a
	// single length byte followed by the auth response bytes.
	buf = append(buf, byte(len(authResponse)))
	buf = append(buf, authResponse...)

	if caps&capConnectWithDB != 0 {
		buf = appendNullTerminated(buf, database)
	}
	if caps&capPluginAuth != 0 {
		buf = appendNullTerminated(buf, "mysql_native_password")
	}
	return buf
}
