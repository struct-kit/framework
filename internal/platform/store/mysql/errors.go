package mysql

import "fmt"

// duplicateEntryErrorCode is ER_DUP_ENTRY — MySQL's error code for a
// unique-constraint violation, the equivalent of Postgres's SQLSTATE
// 23505. UserRepository.Create maps this to apperr.Conflict one layer up.
const duplicateEntryErrorCode = 1062

// MySQLError is a structured ERR_Packet from the server.
type MySQLError struct {
	Code     uint16
	SQLState string
	Message  string
}

func (e *MySQLError) Error() string {
	return fmt.Sprintf("mysql: %s (error %d, SQLSTATE %s)", e.Message, e.Code, e.SQLState)
}

func (e *MySQLError) IsDuplicateEntry() bool { return e.Code == duplicateEntryErrorCode }

// parseErrPacket decodes an ERR_Packet payload. Assumes CLIENT_PROTOCOL_41
// (always set by this driver — see clientCapabilities), so a SQL state
// marker and 5-byte SQL state always follow the error code.
func parseErrPacket(payload []byte) (*MySQLError, error) {
	if len(payload) < 3 || payload[0] != headerErr {
		return nil, fmt.Errorf("mysql: not an ERR packet")
	}
	code := uint16(payload[1]) | uint16(payload[2])<<8
	pos := 3

	sqlState := ""
	if pos < len(payload) && payload[pos] == '#' {
		pos++
		end := pos + 5
		if end > len(payload) {
			return nil, fmt.Errorf("mysql: truncated ERR packet SQL state")
		}
		sqlState = string(payload[pos:end])
		pos = end
	}

	message := string(payload[pos:])
	return &MySQLError{Code: code, SQLState: sqlState, Message: message}, nil
}
