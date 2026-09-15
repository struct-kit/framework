package mysql

import (
	"context"
	"fmt"
)

// serverMoreResultsExists is a status-flag bit meaning "another result
// set follows this one" — set when CLIENT_MULTI_STATEMENTS carries
// several ;-separated statements in one COM_QUERY.
const serverMoreResultsExists = 0x0008

// executeText runs query via COM_QUERY (the text protocol). Used only for
// trusted, non-parameterized SQL — migration scripts and BEGIN/COMMIT/
// ROLLBACK — never for anything carrying user-supplied values, which
// always goes through the binary protocol's real parameter binding
// (binary_protocol.go). Any rows a statement happens to return are
// discarded; this driver's only text-protocol caller (migrations, simple
// transaction control) never needs them.
func (c *Conn) executeText(ctx context.Context, query string) error {
	return c.withDeadline(ctx, func() error {
		payload := append([]byte{comQuery}, query...)
		if err := writePacket(c.w, 0, payload); err != nil {
			return err
		}
		if err := c.w.Flush(); err != nil {
			return err
		}
		return c.readTextResultSets()
	})
}

func (c *Conn) readTextResultSets() error {
	for {
		more, err := c.readOneTextResultSet()
		if err != nil {
			return err
		}
		if !more {
			return nil
		}
	}
}

func (c *Conn) readOneTextResultSet() (more bool, err error) {
	pkt, err := readPacket(c.r)
	if err != nil {
		return false, err
	}
	if len(pkt.Payload) == 0 {
		return false, fmt.Errorf("mysql: empty result packet")
	}

	switch pkt.Payload[0] {
	case headerErr:
		mysqlErr, perr := parseErrPacket(pkt.Payload)
		if perr != nil {
			return false, fmt.Errorf("mysql: server returned an error (and it was unparseable)")
		}
		return false, mysqlErr

	case headerOK:
		status, err := okPacketStatusFlags(pkt.Payload)
		if err != nil {
			return false, err
		}
		return status&serverMoreResultsExists != 0, nil

	default:
		// A result set: the payload is a length-encoded column count.
		columnCount, _, _, err := readLenEncInt(pkt.Payload, 0)
		if err != nil {
			return false, err
		}
		for i := uint64(0); i < columnCount; i++ {
			if _, err := readPacket(c.r); err != nil {
				return false, err
			}
		}
		if _, err := c.expectEOF(); err != nil {
			return false, err
		}
		for {
			rowPkt, err := readPacket(c.r)
			if err != nil {
				return false, err
			}
			if isEOFPacket(rowPkt.Payload) {
				status, err := eofPacketStatusFlags(rowPkt.Payload)
				if err != nil {
					return false, err
				}
				return status&serverMoreResultsExists != 0, nil
			}
			if len(rowPkt.Payload) > 0 && rowPkt.Payload[0] == headerErr {
				mysqlErr, perr := parseErrPacket(rowPkt.Payload)
				if perr != nil {
					return false, fmt.Errorf("mysql: server error mid-resultset (unparseable)")
				}
				return false, mysqlErr
			}
			// row data — discarded, see doc comment above.
		}
	}
}

func isEOFPacket(payload []byte) bool {
	return len(payload) > 0 && payload[0] == headerEOF && len(payload) < 9
}

func eofPacketStatusFlags(payload []byte) (uint16, error) {
	if len(payload) < 5 {
		return 0, fmt.Errorf("mysql: malformed EOF packet")
	}
	return uint16(payload[3]) | uint16(payload[4])<<8, nil
}

// okPacketStatusFlags parses just enough of an OK_Packet (header,
// affected-rows, last-insert-id, then the 2-byte status flags this
// function wants) to check the "more results follow" bit.
func okPacketStatusFlags(payload []byte) (uint16, error) {
	pos := 1
	_, _, pos, err := readLenEncInt(payload, pos) // affected rows
	if err != nil {
		return 0, err
	}
	_, _, pos, err = readLenEncInt(payload, pos) // last insert id
	if err != nil {
		return 0, err
	}
	if pos+2 > len(payload) {
		return 0, fmt.Errorf("mysql: malformed OK packet (status flags)")
	}
	return uint16(payload[pos]) | uint16(payload[pos+1])<<8, nil
}

func (c *Conn) expectEOF() (uint16, error) {
	pkt, err := readPacket(c.r)
	if err != nil {
		return 0, err
	}
	if !isEOFPacket(pkt.Payload) {
		if len(pkt.Payload) > 0 && pkt.Payload[0] == headerErr {
			if mysqlErr, perr := parseErrPacket(pkt.Payload); perr == nil {
				return 0, mysqlErr
			}
		}
		return 0, fmt.Errorf("mysql: expected an EOF packet")
	}
	return eofPacketStatusFlags(pkt.Payload)
}
