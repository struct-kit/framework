package controllers

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"struct-framework/internal/mvc/apperr"
	"struct-framework/internal/platform/http/appctx"
	"struct-framework/internal/platform/http/middleware"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 1024)
		return &b
	},
}

type errorResponse struct {
	Error     string            `json:"error"`
	Code      string            `json:"code,omitempty"`
	RequestID string            `json:"request_id,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, message string, fields map[string]string) {
	writeJSON(w, status, errorResponse{
		Error:  message,
		Fields: fields,
	})
}

func writeErrorWithRequest(w http.ResponseWriter, r *http.Request, status int, code, message string, fields map[string]string) {
	reqID := ""
	if r != nil {
		reqID = appctx.RequestID(r.Context())
	}
	writeJSON(w, status, errorResponse{
		Error:     message,
		Code:      code,
		RequestID: reqID,
		Fields:    fields,
	})
}

func writeServiceError(w http.ResponseWriter, err error) {
	appErr, ok := apperr.As(err)
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal error", nil)
		return
	}
	status := appErr.HTTPStatus()
	writeJSON(w, status, errorResponse{
		Error:  appErr.Message,
		Code:   appErr.Code,
		Fields: appErr.Fields,
	})
}

// requireUserID verifies that a valid user identity is attached to the request context,
// returning (userID, true) or rendering 401 Unauthorized and returning ("", false).
func requireUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	if uid, ok := appctx.UserID(r.Context()); ok {
		return uid, true
	}
	userID, ok := middleware.UserIDFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, translate(r, "errors.authentication_required"), nil)
		return "", false
	}
	return userID, true
}

// decodeJSON reads and decodes JSON from r.Body with a 1MB limit and strict field checking.
func decodeJSON(w http.ResponseWriter, r *http.Request, dest any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		writeError(w, http.StatusBadRequest, translate(r, "errors.invalid_request_body"), nil)
		return false
	}
	return true
}
