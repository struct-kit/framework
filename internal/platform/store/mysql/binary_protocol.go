// Binary protocol support: COM_STMT_PREPARE / COM_STMT_EXECUTE /
// COM_STMT_CLOSE. This is the only path user-supplied values ever travel
// through (framework guide §5.4: "never string-concatenated SQL") — the
// text protocol (text_protocol.go) is reserved for trusted, fixed SQL.
//
// This file is the highest-risk in the entire codebase: the NULL bitmap
// for result rows uses a 2-bit offset that's easy to get subtly wrong,
// and DATETIME/TIMESTAMP values are packed into a variable-length
// structure keyed by its own leading length byte. Every layout below is
// written from protocol-specification knowledge; none of it has been
// run against a real server. If a bug is going to be hiding anywhere in
// this codebase, it's here first.
package mysql

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"time"
)

// Column type bytes this driver can decode in a binary result row. Values
// are MySQL's well-known protocol constants.
const (
	fieldTypeDecimal    = 0x00
	fieldTypeTiny       = 0x01
	fieldTypeShort      = 0x02
	fieldTypeLong       = 0x03
	fieldTypeFloat      = 0x04
	fieldTypeDouble     = 0x05
	fieldTypeTimestamp  = 0x07
	fieldTypeLongLong   = 0x08
	fieldTypeInt24      = 0x09
	fieldTypeDate       = 0x0a
	fieldTypeDatetime   = 0x0c
	fieldTypeYear       = 0x0d
	fieldTypeVarchar    = 0x0f
	fieldTypeNewDecimal = 0xf6
	fieldTypeTinyBlob   = 0xf9
	fieldTypeMediumBlob = 0xfa
	fieldTypeLongBlob   = 0xfb
	fieldTypeBlob       = 0xfc
	fieldTypeVarString  = 0xfd
	fieldTypeString     = 0xfe
)

type preparedStatement struct {
	id        uint32
	numParams int
}

// prepareStatement sends COM_STMT_PREPARE and consumes its response —
// COM_STMT_PREPARE_OK, then that many parameter and column definition
// packets (each terminated by an EOF, since CLIENT_DEPRECATE_EOF is not
// set). Parameter/column definition contents aren't needed here: params
// are always bound as strings (buildExecutePayload), and result column
// types are read fresh from each EXECUTE response instead of cached from
// PREPARE, since EXECUTE's response repeats them anyway.
func (c *Conn) prepareStatement(ctx context.Context, query string) (*preparedStatement, error) {
	var stmt *preparedStatement
	err := c.withDeadline(ctx, func() error {
		payload := append([]byte{comStmtPrepare}, query...)
		if err := writePacket(c.w, 0, payload); err != nil {
			return err
		}
		if err := c.w.Flush(); err != nil {
			return err
		}

		pkt, err := readPacket(c.r)
		if err != nil {
			return err
		}
		if len(pkt.Payload) > 0 && pkt.Payload[0] == headerErr {
			mysqlErr, perr := parseErrPacket(pkt.Payload)
			if perr != nil {
				return fmt.Errorf("mysql: prepare failed (unparseable error)")
			}
			return mysqlErr
		}
		if len(pkt.Payload) < 12 || pkt.Payload[0] != 0x00 {
			return fmt.Errorf("mysql: malformed COM_STMT_PREPARE_OK packet")
		}
		stmtID := binary.LittleEndian.Uint32(pkt.Payload[1:5])
		numColumns := int(binary.LittleEndian.Uint16(pkt.Payload[5:7]))
		numParams := int(binary.LittleEndian.Uint16(pkt.Payload[7:9]))
		// pkt.Payload[9] is a filler byte, [10:12] is the warning count —
		// neither is needed here.

		for i := 0; i < numParams; i++ {
			if _, err := readPacket(c.r); err != nil {
				return err
			}
		}
		if numParams > 0 {
			if _, err := c.expectEOF(); err != nil {
				return err
			}
		}
		for i := 0; i < numColumns; i++ {
			if _, err := readPacket(c.r); err != nil {
				return err
			}
		}
		if numColumns > 0 {
			if _, err := c.expectEOF(); err != nil {
				return err
			}
		}

		stmt = &preparedStatement{id: stmtID, numParams: numParams}
		return nil
	})
	return stmt, err
}

func (c *Conn) closeStatement(ctx context.Context, stmt *preparedStatement) error {
	return c.withDeadline(ctx, func() error {
		payload := make([]byte, 5)
		payload[0] = comStmtClose
		binary.LittleEndian.PutUint32(payload[1:5], stmt.id)
		if err := writePacket(c.w, 0, payload); err != nil {
			return err
		}
		return c.w.Flush()
		// COM_STMT_CLOSE has no response packet — nothing more to read.
	})
}

type mysqlResultSet struct {
	rows         [][][]byte
	affectedRows int64
}

// executeStatement sends COM_STMT_EXECUTE with args bound as real
// parameters (never string-concatenated into the query text) and reads
// whichever response shape follows: an OK packet for a write, or a
// binary result set for a read.
func (c *Conn) executeStatement(ctx context.Context, stmt *preparedStatement, args []any) (*mysqlResultSet, error) {
	var rs *mysqlResultSet
	err := c.withDeadline(ctx, func() error {
		payload, err := buildExecutePayload(stmt, args)
		if err != nil {
			return err
		}
		if err := writePacket(c.w, 0, payload); err != nil {
			return err
		}
		if err := c.w.Flush(); err != nil {
			return err
		}

		pkt, err := readPacket(c.r)
		if err != nil {
			return err
		}
		if len(pkt.Payload) == 0 {
			return fmt.Errorf("mysql: empty COM_STMT_EXECUTE response")
		}

		switch pkt.Payload[0] {
		case headerErr:
			mysqlErr, perr := parseErrPacket(pkt.Payload)
			if perr != nil {
				return fmt.Errorf("mysql: execute failed (unparseable error)")
			}
			return mysqlErr

		case headerOK:
			affected, _, _, err := readLenEncInt(pkt.Payload, 1)
			if err != nil {
				return err
			}
			rs = &mysqlResultSet{affectedRows: int64(affected)}
			return nil

		default:
			columnCount, _, _, err := readLenEncInt(pkt.Payload, 0)
			if err != nil {
				return err
			}
			columnTypes := make([]byte, columnCount)
			for i := uint64(0); i < columnCount; i++ {
				colPkt, err := readPacket(c.r)
				if err != nil {
					return err
				}
				typ, err := parseColumnDefinitionType(colPkt.Payload)
				if err != nil {
					return err
				}
				columnTypes[i] = typ
			}
			if _, err := c.expectEOF(); err != nil {
				return err
			}

			result := &mysqlResultSet{}
			for {
				rowPkt, err := readPacket(c.r)
				if err != nil {
					return err
				}
				if isEOFPacket(rowPkt.Payload) {
					rs = result
					return nil
				}
				if len(rowPkt.Payload) > 0 && rowPkt.Payload[0] == headerErr {
					mysqlErr, perr := parseErrPacket(rowPkt.Payload)
					if perr != nil {
						return fmt.Errorf("mysql: server error mid-resultset (unparseable)")
					}
					return mysqlErr
				}
				row, err := decodeBinaryRow(rowPkt.Payload, columnTypes)
				if err != nil {
					return err
				}
				result.rows = append(result.rows, row)
			}
		}
	})
	return rs, err
}

// buildExecutePayload always binds parameters as MYSQL_TYPE_VAR_STRING —
// a string, length-encoded — regardless of the target column's real
// type, relying on MySQL's standard implicit conversion from a bound
// string to whatever the column actually is. This is a deliberate
// simplification: it avoids needing a correct binary encoding for every
// numeric/date type on the parameter side (the highest-risk code in this
// package is decoding results; this keeps the encoding side simple and
// well-trodden — string bind parameters are extremely common practice).
func buildExecutePayload(stmt *preparedStatement, args []any) ([]byte, error) {
	if stmt.numParams != len(args) {
		return nil, fmt.Errorf("mysql: statement expects %d parameters, got %d", stmt.numParams, len(args))
	}

	var buf []byte
	buf = append(buf, comStmtExecute)
	buf = binary.LittleEndian.AppendUint32(buf, stmt.id)
	buf = append(buf, 0x00)                        // flags: CURSOR_TYPE_NO_CURSOR
	buf = binary.LittleEndian.AppendUint32(buf, 1) // iteration count, always 1

	if stmt.numParams == 0 {
		return buf, nil
	}

	bitmapLen := (stmt.numParams + 7) / 8
	nullBitmap := make([]byte, bitmapLen)
	encoded := make([][]byte, stmt.numParams)
	isNull := make([]bool, stmt.numParams)

	for i, a := range args {
		enc, null, err := encodeParamAsString(a)
		if err != nil {
			return nil, err
		}
		isNull[i] = null
		if null {
			nullBitmap[i/8] |= 1 << uint(i%8)
		} else {
			encoded[i] = enc
		}
	}

	buf = append(buf, nullBitmap...)
	buf = append(buf, 0x01) // new-params-bind-flag: yes, types follow
	for range args {
		buf = append(buf, fieldTypeVarString, 0x00) // type byte + unsigned flag
	}
	for i := range args {
		if isNull[i] {
			continue
		}
		buf = appendLenEncString(buf, encoded[i])
	}
	return buf, nil
}

func encodeParamAsString(a any) (encoded []byte, isNull bool, err error) {
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
			return []byte("1"), false, nil
		}
		return []byte("0"), false, nil
	case time.Time:
		return []byte(v.UTC().Format("2006-01-02 15:04:05.000000")), false, nil
	default:
		return nil, false, fmt.Errorf("mysql: unsupported parameter type %T", a)
	}
}

// parseColumnDefinitionType extracts just the type byte from a Column
// Definition packet: six length-encoded strings (catalog, schema, table,
// org_table, name, org_name), then a fixed block — a length-encoded
// filler (always 0x0c), 2-byte charset, 4-byte column length, then the
// 1-byte type this function returns (flags/decimals/filler follow, and
// aren't needed here).
func parseColumnDefinitionType(payload []byte) (byte, error) {
	pos := 0
	for i := 0; i < 6; i++ {
		_, _, next, err := readLenEncString(payload, pos)
		if err != nil {
			return 0, fmt.Errorf("mysql: parsing column definition field %d: %w", i, err)
		}
		pos = next
	}
	pos++    // the 0x0c filler-length byte itself
	pos += 2 // charset
	pos += 4 // column length
	if pos >= len(payload) {
		return 0, fmt.Errorf("mysql: truncated column definition (type byte)")
	}
	return payload[pos], nil
}

// resultNullBitmapLength and nullBitmapIsSet implement the binary
// protocol resultset row's NULL bitmap exactly as documented: length
// (numColumns + 7 + 2) / 8 bytes, with column i's presence bit at bit
// position (i+2) — the "+2" reserves the first two bits, unlike
// COM_STMT_EXECUTE's parameter NULL bitmap, which has no such offset.
// Mixing these two up is the single easiest way to corrupt every row
// after the first NULL column; this comment exists so nobody "simplifies"
// the offset away later.
func resultNullBitmapLength(numColumns int) int {
	return (numColumns + 7 + 2) / 8
}

func nullBitmapIsSet(bitmap []byte, columnIndex int) bool {
	bitIndex := columnIndex + 2
	bytePos := bitIndex / 8
	bitPos := bitIndex % 8
	if bytePos >= len(bitmap) {
		return false
	}
	return bitmap[bytePos]&(1<<uint(bitPos)) != 0
}

func decodeBinaryRow(payload []byte, columnTypes []byte) ([][]byte, error) {
	if len(payload) < 1 || payload[0] != 0x00 {
		return nil, fmt.Errorf("mysql: malformed binary row (missing packet header)")
	}
	pos := 1
	numCols := len(columnTypes)
	bitmapLen := resultNullBitmapLength(numCols)
	if pos+bitmapLen > len(payload) {
		return nil, fmt.Errorf("mysql: truncated binary row (NULL bitmap)")
	}
	bitmap := payload[pos : pos+bitmapLen]
	pos += bitmapLen

	row := make([][]byte, numCols)
	for i := 0; i < numCols; i++ {
		if nullBitmapIsSet(bitmap, i) {
			row[i] = nil
			continue
		}
		val, next, err := decodeBinaryValue(payload, pos, columnTypes[i])
		if err != nil {
			return nil, fmt.Errorf("mysql: decoding column %d: %w", i, err)
		}
		row[i] = val
		pos = next
	}
	return row, nil
}

// decodeBinaryValue converts one binary-protocol column value into its
// canonical text representation ([]byte), so downstream scanning
// (rows.go's scanValue) is identical to the text protocol's and to the
// postgres package's — the same destination-typed conversion from raw
// bytes, regardless of which wire format produced them.
func decodeBinaryValue(payload []byte, pos int, colType byte) (value []byte, next int, err error) {
	switch colType {
	case fieldTypeTiny:
		if pos+1 > len(payload) {
			return nil, pos, fmt.Errorf("truncated TINY value")
		}
		return []byte(strconv.Itoa(int(int8(payload[pos])))), pos + 1, nil

	case fieldTypeShort, fieldTypeYear:
		if pos+2 > len(payload) {
			return nil, pos, fmt.Errorf("truncated SHORT value")
		}
		v := int16(binary.LittleEndian.Uint16(payload[pos : pos+2]))
		return []byte(strconv.Itoa(int(v))), pos + 2, nil

	case fieldTypeLong, fieldTypeInt24:
		if pos+4 > len(payload) {
			return nil, pos, fmt.Errorf("truncated LONG value")
		}
		v := int32(binary.LittleEndian.Uint32(payload[pos : pos+4]))
		return []byte(strconv.Itoa(int(v))), pos + 4, nil

	case fieldTypeLongLong:
		if pos+8 > len(payload) {
			return nil, pos, fmt.Errorf("truncated LONGLONG value")
		}
		v := int64(binary.LittleEndian.Uint64(payload[pos : pos+8]))
		return []byte(strconv.FormatInt(v, 10)), pos + 8, nil

	case fieldTypeFloat:
		if pos+4 > len(payload) {
			return nil, pos, fmt.Errorf("truncated FLOAT value")
		}
		bits := binary.LittleEndian.Uint32(payload[pos : pos+4])
		return []byte(strconv.FormatFloat(float64(math.Float32frombits(bits)), 'f', -1, 32)), pos + 4, nil

	case fieldTypeDouble:
		if pos+8 > len(payload) {
			return nil, pos, fmt.Errorf("truncated DOUBLE value")
		}
		bits := binary.LittleEndian.Uint64(payload[pos : pos+8])
		return []byte(strconv.FormatFloat(math.Float64frombits(bits), 'f', -1, 64)), pos + 8, nil

	case fieldTypeDate, fieldTypeDatetime, fieldTypeTimestamp:
		return decodeBinaryDateTime(payload, pos)

	case fieldTypeVarchar, fieldTypeVarString, fieldTypeString,
		fieldTypeTinyBlob, fieldTypeMediumBlob, fieldTypeLongBlob, fieldTypeBlob,
		fieldTypeDecimal, fieldTypeNewDecimal:
		strVal, isNull, next, err := readLenEncString(payload, pos)
		if err != nil {
			return nil, pos, err
		}
		if isNull {
			return nil, next, fmt.Errorf("mysql: unexpected NULL marker outside the row's NULL bitmap")
		}
		return strVal, next, nil

	default:
		return nil, pos, fmt.Errorf("mysql: unsupported binary column type 0x%x", colType)
	}
}

// decodeBinaryDateTime decodes MySQL's packed DATE/DATETIME/TIMESTAMP
// structure: a 1-byte length (0, 4, 7, or 11) that determines which
// fields follow, then year(2 LE)/month(1)/day(1)/[hour(1)/minute(1)/
// second(1)]/[microsecond(4 LE)].
func decodeBinaryDateTime(payload []byte, pos int) (value []byte, next int, err error) {
	if pos >= len(payload) {
		return nil, pos, fmt.Errorf("truncated datetime length byte")
	}
	length := int(payload[pos])
	pos++
	if length == 0 {
		return []byte("0000-00-00 00:00:00.000000"), pos, nil
	}
	if pos+length > len(payload) {
		return nil, pos, fmt.Errorf("truncated datetime value (want %d bytes)", length)
	}

	year := int(binary.LittleEndian.Uint16(payload[pos : pos+2]))
	month := int(payload[pos+2])
	day := int(payload[pos+3])
	hour, minute, second, micro := 0, 0, 0, 0
	if length >= 7 {
		hour = int(payload[pos+4])
		minute = int(payload[pos+5])
		second = int(payload[pos+6])
	}
	if length >= 11 {
		micro = int(binary.LittleEndian.Uint32(payload[pos+7 : pos+11]))
	}

	formatted := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d.%06d", year, month, day, hour, minute, second, micro)
	return []byte(formatted), pos + length, nil
}
