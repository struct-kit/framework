package mysql

import (
	"fmt"
	"strconv"
	"time"

	"struct-framework/internal/platform/store"
)

type execResult struct {
	affectedRows int64
}

func (r execResult) RowsAffected() (int64, error) { return r.affectedRows, nil }

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
		return fmt.Errorf("mysql: Scan called without a successful call to Next")
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
		return fmt.Errorf("mysql: scan target count %d does not match column count %d", len(dest), len(row))
	}
	for i, d := range dest {
		if err := scanValue(row[i], d); err != nil {
			return fmt.Errorf("mysql: scanning column %d: %w", i, err)
		}
	}
	return nil
}

// scanValue mirrors the postgres package's scanValue exactly: positional,
// destination-typed conversion from a canonical text representation —
// here, decodeBinaryValue has already converted every column to that
// representation, so this function never needs to know the original wire
// format (text vs. binary protocol).
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
		*d = string(raw) == "1" || string(raw) == "t"
		return nil
	case *time.Time:
		if raw == nil {
			*d = time.Time{}
			return nil
		}
		t, err := time.Parse("2006-01-02 15:04:05.000000", string(raw))
		if err != nil {
			return fmt.Errorf("mysql: could not parse timestamp %q: %w", raw, err)
		}
		*d = t
		return nil
	default:
		return fmt.Errorf("unsupported scan destination type %T", dest)
	}
}

var (
	_ store.Result = execResult{}
	_ store.Rows   = (*rowsImpl)(nil)
	_ store.Row    = (*rowImpl)(nil)
)
