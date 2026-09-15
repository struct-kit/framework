// Package apperr defines the typed error contract shared between services
// and controllers. Services never return raw fmt.Errorf strings for
// expected failure modes — they return one of these sentinel-wrapped kinds,
// and the HTTP layer maps each kind to a status code in exactly one place.
package apperr

import (
	"errors"
	"fmt"
	"net/http"
)

type Kind int

const (
	KindUnknown Kind = iota
	KindNotFound
	KindConflict
	KindValidation
	KindUnauthorized
	KindForbidden
	KindLocked
	KindBadRequest
	KindTooManyRequests
	KindTimeout
	KindUnavailable
	KindInternal
)

// String returns a readable representation of the Kind.
func (k Kind) String() string {
	switch k {
	case KindNotFound:
		return "not_found"
	case KindConflict:
		return "conflict"
	case KindValidation:
		return "validation"
	case KindUnauthorized:
		return "unauthorized"
	case KindForbidden:
		return "forbidden"
	case KindLocked:
		return "locked"
	case KindBadRequest:
		return "bad_request"
	case KindTooManyRequests:
		return "too_many_requests"
	case KindTimeout:
		return "timeout"
	case KindUnavailable:
		return "unavailable"
	case KindInternal:
		return "internal"
	default:
		return "unknown"
	}
}

// HTTPStatus returns the canonical HTTP status code for this Kind.
func (k Kind) HTTPStatus() int {
	switch k {
	case KindNotFound:
		return http.StatusNotFound
	case KindConflict:
		return http.StatusConflict
	case KindValidation:
		return http.StatusUnprocessableEntity
	case KindUnauthorized:
		return http.StatusUnauthorized
	case KindForbidden:
		return http.StatusForbidden
	case KindLocked:
		return http.StatusLocked
	case KindBadRequest:
		return http.StatusBadRequest
	case KindTooManyRequests:
		return http.StatusTooManyRequests
	case KindTimeout:
		return http.StatusGatewayTimeout
	case KindUnavailable:
		return http.StatusServiceUnavailable
	case KindInternal:
		return http.StatusInternalServerError
	default:
		return http.StatusInternalServerError
	}
}

// DefaultCode returns the canonical machine-readable error code for this Kind.
func (k Kind) DefaultCode() string {
	switch k {
	case KindNotFound:
		return "NOT_FOUND"
	case KindConflict:
		return "RESOURCE_CONFLICT"
	case KindValidation:
		return "VALIDATION_FAILED"
	case KindUnauthorized:
		return "UNAUTHORIZED"
	case KindForbidden:
		return "FORBIDDEN"
	case KindLocked:
		return "ACCOUNT_LOCKED"
	case KindBadRequest:
		return "BAD_REQUEST"
	case KindTooManyRequests:
		return "RATE_LIMIT_EXCEEDED"
	case KindTimeout:
		return "REQUEST_TIMEOUT"
	case KindUnavailable:
		return "SERVICE_UNAVAILABLE"
	case KindInternal:
		return "INTERNAL_SERVER_ERROR"
	default:
		return "INTERNAL_ERROR"
	}
}

// Error is the typed application error. Callers should use errors.As to
// recover the Kind, Code, and Fields rather than string-matching Error().
type Error struct {
	Kind    Kind
	Code    string
	Message string
	Fields  map[string]string // field -> validation message, for KindValidation
	cause   error
}

func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.cause)
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.cause }

func (e *Error) WithCode(code string) *Error {
	e.Code = code
	return e
}

func (e *Error) WithCause(cause error) *Error {
	e.cause = cause
	return e
}

func (e *Error) HTTPStatus() int {
	return e.Kind.HTTPStatus()
}

func NotFound(msg string) *Error {
	return &Error{Kind: KindNotFound, Code: KindNotFound.DefaultCode(), Message: msg}
}

func Conflict(msg string) *Error {
	return &Error{Kind: KindConflict, Code: KindConflict.DefaultCode(), Message: msg}
}

func Unauthorized(msg string) *Error {
	return &Error{Kind: KindUnauthorized, Code: KindUnauthorized.DefaultCode(), Message: msg}
}

func Forbidden(msg string) *Error {
	return &Error{Kind: KindForbidden, Code: KindForbidden.DefaultCode(), Message: msg}
}

func Locked(msg string) *Error {
	return &Error{Kind: KindLocked, Code: KindLocked.DefaultCode(), Message: msg}
}

func BadRequest(msg string) *Error {
	return &Error{Kind: KindBadRequest, Code: KindBadRequest.DefaultCode(), Message: msg}
}

func TooManyRequests(msg string) *Error {
	return &Error{Kind: KindTooManyRequests, Code: KindTooManyRequests.DefaultCode(), Message: msg}
}

func Timeout(msg string) *Error {
	return &Error{Kind: KindTimeout, Code: KindTimeout.DefaultCode(), Message: msg}
}

func Unavailable(msg string) *Error {
	return &Error{Kind: KindUnavailable, Code: KindUnavailable.DefaultCode(), Message: msg}
}

func Internal(msg string, cause error) *Error {
	return &Error{Kind: KindInternal, Code: KindInternal.DefaultCode(), Message: msg, cause: cause}
}

func Validation(fields map[string]string) *Error {
	return &Error{
		Kind:    KindValidation,
		Code:    KindValidation.DefaultCode(),
		Message: "validation failed",
		Fields:  fields,
	}
}

func Wrap(kind Kind, msg string, cause error) *Error {
	return &Error{Kind: kind, Code: kind.DefaultCode(), Message: msg, cause: cause}
}

// As is a convenience wrapper around errors.As for pulling an *Error out of an error chain.
func As(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
