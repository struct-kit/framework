package postgres

import "fmt"

// PgError is a structured ErrorResponse from the server. SQLSTATE codes
// are 5-character strings per the Postgres manual's appendix; 23505 is
// unique_violation, which UserRepository.Create maps to apperr.Conflict.
type PgError struct {
	Severity string
	Code     string
	Message  string
}

func (e *PgError) Error() string {
	return fmt.Sprintf("postgres: %s: %s (SQLSTATE %s)", e.Severity, e.Message, e.Code)
}

func (e *PgError) IsUniqueViolation() bool { return e.Code == "23505" }

// parseErrorResponse decodes an ErrorResponse payload: a sequence of
// (1-byte field type, C string value) pairs, terminated by a single zero
// byte. Field type codes we care about: 'S' severity, 'C' SQLSTATE,
// 'M' primary human-readable message. Others (detail, hint, position,
// etc.) are skipped.
func parseErrorResponse(payload []byte) *PgError {
	e := &PgError{}
	i := 0
	for i < len(payload) {
		fieldType := payload[i]
		i++
		if fieldType == 0 {
			break
		}
		start := i
		for i < len(payload) && payload[i] != 0 {
			i++
		}
		value := string(payload[start:i])
		if i < len(payload) {
			i++ // skip the NUL terminator
		}
		switch fieldType {
		case 'S':
			e.Severity = value
		case 'C':
			e.Code = value
		case 'M':
			e.Message = value
		}
	}
	return e
}
