package tests

import (
	"errors"
	"net/http"
	"testing"

	"struct-framework/internal/mvc/apperr"
)

func TestAppErr_KindsAndCodes(t *testing.T) {
	tests := []struct {
		err        *apperr.Error
		wantKind   apperr.Kind
		wantStatus int
		wantCode   string
	}{
		{apperr.NotFound("not found"), apperr.KindNotFound, http.StatusNotFound, "NOT_FOUND"},
		{apperr.Conflict("conflict"), apperr.KindConflict, http.StatusConflict, "RESOURCE_CONFLICT"},
		{apperr.Unauthorized("unauth"), apperr.KindUnauthorized, http.StatusUnauthorized, "UNAUTHORIZED"},
		{apperr.Forbidden("forbidden"), apperr.KindForbidden, http.StatusForbidden, "FORBIDDEN"},
		{apperr.Locked("locked"), apperr.KindLocked, http.StatusLocked, "ACCOUNT_LOCKED"},
		{apperr.BadRequest("bad req"), apperr.KindBadRequest, http.StatusBadRequest, "BAD_REQUEST"},
		{apperr.TooManyRequests("too many"), apperr.KindTooManyRequests, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED"},
		{apperr.Timeout("timeout"), apperr.KindTimeout, http.StatusGatewayTimeout, "REQUEST_TIMEOUT"},
		{apperr.Unavailable("down"), apperr.KindUnavailable, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"},
		{apperr.Internal("internal", errors.New("db error")), apperr.KindInternal, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR"},
		{apperr.Validation(map[string]string{"email": "invalid"}), apperr.KindValidation, http.StatusUnprocessableEntity, "VALIDATION_FAILED"},
	}

	for _, tt := range tests {
		if tt.err.Kind != tt.wantKind {
			t.Errorf("expected kind %v, got %v", tt.wantKind, tt.err.Kind)
		}
		if tt.err.HTTPStatus() != tt.wantStatus {
			t.Errorf("expected status %d, got %d", tt.wantStatus, tt.err.HTTPStatus())
		}
		if tt.err.Code != tt.wantCode {
			t.Errorf("expected code %s, got %s", tt.wantCode, tt.err.Code)
		}
	}
}

func TestAppErr_UnwrapAndAs(t *testing.T) {
	cause := errors.New("underlying sql connection reset")
	err := apperr.Internal("query failed", cause)

	if !errors.Is(err, cause) {
		t.Errorf("expected errors.Is to match cause")
	}

	if appErr, ok := apperr.As(err); !ok || appErr.Kind != apperr.KindInternal {
		t.Fatalf("apperr.As failed to extract *Error: %v", appErr)
	}

	// Custom code chaining
	custom := apperr.NotFound("user missing").WithCode("USER_NOT_FOUND")
	if custom.Code != "USER_NOT_FOUND" {
		t.Errorf("expected custom code USER_NOT_FOUND, got %s", custom.Code)
	}
}
