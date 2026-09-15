package postgres

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"time"
)

// buildParseMessage builds the payload for a Parse ('P') message using
// the unnamed statement, with zero parameter type OIDs specified — the
// server infers every parameter's type from how it's used in the query
// (e.g. compared against a column), which is sufficient for the plain
// CRUD queries this driver targets.
func buildParseMessage(query string) []byte {
	var buf []byte
	buf = appendCString(buf, "") // unnamed statement
	buf = appendCString(buf, query)
	buf = appendInt16(buf, 0) // 0 = let the server infer all param types
	return buf
}

// buildBindMessage builds the payload for a Bind ('B') message: unnamed
// portal bound to the unnamed statement, all parameters and all result
// columns in text format (format-code count of 0 means "all text" per
// the protocol spec).
func buildBindMessage(args []any) ([]byte, error) {
	var buf []byte
	buf = appendCString(buf, "") // unnamed portal
	buf = appendCString(buf, "") // unnamed statement
	buf = appendInt16(buf, 0)    // param format codes: 0 = all text
	buf = appendInt16(buf, int16(len(args)))
	for _, a := range args {
		encoded, isNull, err := encodeParam(a)
		if err != nil {
			return nil, err
		}
		if isNull {
			buf = appendInt32(buf, -1)
			continue
		}
		buf = appendInt32(buf, int32(len(encoded)))
		buf = append(buf, encoded...)
	}
	buf = appendInt16(buf, 0) // result format codes: 0 = all text
	return buf, nil
}

// buildExecuteMessage builds the payload for an Execute ('E') message
// against the unnamed portal, with no row-count limit.
func buildExecuteMessage() []byte {
	var buf []byte
	buf = appendCString(buf, "")
	buf = appendInt32(buf, 0)
	return buf
}

// encodeParam converts a Go value to its Postgres text-format
// representation. This is a deliberately small, explicit set of types —
// extend it as real query needs arise rather than reaching for
// reflection.
func encodeParam(a any) (encoded []byte, isNull bool, err error) {
	if a == nil {
		return nil, true, nil
	}
	switch v := a.(type) {
	case string:
		return []byte(v), false, nil
	case []byte:
		return v, false, nil
	case int:
		return []byte(strconv.Itoa(v)), false, nil
	case int32:
		return []byte(strconv.FormatInt(int64(v), 10)), false, nil
	case int64:
		return []byte(strconv.FormatInt(v, 10)), false, nil
	case float64:
		return []byte(strconv.FormatFloat(v, 'f', -1, 64)), false, nil
	case bool:
		if v {
			return []byte("t"), false, nil
		}
		return []byte("f"), false, nil
	case time.Time:
		return []byte(v.UTC().Format(time.RFC3339Nano)), false, nil
	default:
		return nil, false, fmt.Errorf("postgres: unsupported parameter type %T", a)
	}
}

// decodeDataRow parses one DataRow payload: an Int16 field count, then
// per field an Int32 length (-1 means SQL NULL) followed by that many
// raw bytes (text format, since we always request text results).
func decodeDataRow(payload []byte) ([][]byte, error) {
	if len(payload) < 2 {
		return nil, fmt.Errorf("postgres: malformed DataRow (too short)")
	}
	numFields := int(int16(binary.BigEndian.Uint16(payload[0:2])))
	pos := 2
	row := make([][]byte, numFields)
	for i := 0; i < numFields; i++ {
		if pos+4 > len(payload) {
			return nil, fmt.Errorf("postgres: malformed DataRow (truncated length at field %d)", i)
		}
		length := int32(binary.BigEndian.Uint32(payload[pos : pos+4]))
		pos += 4
		if length == -1 {
			row[i] = nil
			continue
		}
		end := pos + int(length)
		if length < 0 || end > len(payload) {
			return nil, fmt.Errorf("postgres: malformed DataRow (truncated data at field %d)", i)
		}
		row[i] = payload[pos:end]
		pos = end
	}
	return row, nil
}
