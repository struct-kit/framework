package postgres

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"struct-framework/internal/platform/store"
)

// resultSet is the fully-buffered outcome of one executeExtended call.
// Buffering the whole result in memory (rather than streaming DataRow
// messages incrementally) is a deliberate bootstrap-phase simplification
// — fine for the CRUD-sized result sets this driver targets today.
type resultSet struct {
	rows       [][][]byte
	commandTag string
}

type execResult struct {
	tag string
}

// RowsAffected parses the trailing integer off a command tag such as
// "INSERT 0 1" or "UPDATE 3". Not every tag ends in a count (e.g.
// "BEGIN") — those report 0 rather than erroring.
func (r execResult) RowsAffected() (int64, error) {
	fields := strings.Fields(r.tag)
	if len(fields) == 0 {
		return 0, nil
	}
	n, err := strconv.ParseInt(fields[len(fields)-1], 10, 64)
	if err != nil {
		return 0, nil
	}
	return n, nil
}

type rowsImpl struct {
	rows [][][]byte
	pos  int
}

func (r *rowsImpl) Next() bool {
	if r.pos >= len(r.rows) {
		return false
	}
	r.pos++
	return true
}

func (r *rowsImpl) Scan(dest ...any) error {
	if r.pos == 0 || r.pos > len(r.rows) {
		return fmt.Errorf("postgres: Scan called without a successful call to Next")
	}
	return scanRow(r.rows[r.pos-1], dest)
}

func (r *rowsImpl) Close() error { return nil }

type rowImpl struct {
	row [][]byte
	err error
}

func (r *rowImpl) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	return scanRow(r.row, dest)
}

func scanRow(row [][]byte, dest []any) error {
	if len(dest) != len(row) {
		return fmt.Errorf("postgres: scan target count %d does not match column count %d", len(dest), len(row))
	}
	for i, d := range dest {
		if err := scanValue(row[i], d); err != nil {
			return fmt.Errorf("postgres: scanning column %d: %w", i, err)
		}
	}
	return nil
}

// scanValue converts one text-format column value into dest, based on
// dest's concrete pointer type — the same positional, destination-typed
// approach database/sql uses, chosen here so this driver never needs
// RowDescription (and therefore never needs a Describe round trip) to
// know how to decode a result.
func scanValue(raw []byte, dest any) error {
	switch d := dest.(type) {
	case *string:
		*d = string(raw)
		return nil
	case *[]byte:
		if raw == nil {
			*d = nil
			return nil
		}
		b := make([]byte, len(raw))
		copy(b, raw)
		*d = b
		return nil
	case *int:
		if raw == nil {
			*d = 0
			return nil
		}
		n, err := strconv.Atoi(string(raw))
		if err != nil {
			return err
		}
		*d = n
		return nil
	case *int64:
		if raw == nil {
			*d = 0
			return nil
		}
		n, err := strconv.ParseInt(string(raw), 10, 64)
		if err != nil {
			return err
		}
		*d = n
		return nil
	case *bool:
		if raw == nil {
			*d = false
			return nil
		}
		*d = string(raw) == "t"
		return nil
	case *time.Time:
		if raw == nil {
			*d = time.Time{}
			return nil
		}
		t, err := parsePgTimestamp(string(raw))
		if err != nil {
			return err
		}
		*d = t
		return nil
	default:
		return fmt.Errorf("unsupported scan destination type %T", dest)
	}
}

// pgTimestampLayouts assumes the session has run `SET DATESTYLE = 'ISO'`
// (conn.go's normalizeSession does this right after auth), so server
// output is one of these forms. Go's reference-time parser treats a
// ".999999"-style fractional segment as optional, so each layout also
// matches the same timestamp without a fractional part.
var pgTimestampLayouts = []string{
	"2006-01-02 15:04:05.999999-07:00",
	"2006-01-02 15:04:05.999999-07",
	time.RFC3339Nano,
}

func parsePgTimestamp(s string) (time.Time, error) {
	var lastErr error
	for _, layout := range pgTimestampLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		} else {
			lastErr = err
		}
	}
	return time.Time{}, fmt.Errorf("postgres: could not parse timestamp %q: %w", s, lastErr)
}

// ensure the dialect package actually satisfies store's result interfaces
// at compile time.
var (
	_ store.Result = execResult{}
	_ store.Rows   = (*rowsImpl)(nil)
	_ store.Row    = (*rowImpl)(nil)
)
