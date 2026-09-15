package rpc

import (
	"context"
	"encoding/json"
	"net/http"
)

// Handle wraps a typed (context.Context, Req) -> (Resp, error) function
// into an http.HandlerFunc: decode the JSON request body into Req, call
// fn, encode its Resp as the JSON response. This is Client.Call's
// server-side counterpart — together they're this pass's stand-in for
// what a .proto-generated client/server pair would give in the framework
// guide's original gRPC design (see this package's doc comment).
func Handle[Req any, Resp any](fn func(ctx context.Context, req Req) (Resp, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req Req
		if r.Body != nil && r.ContentLength != 0 {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeRPCError(w, http.StatusBadRequest, "invalid request body")
				return
			}
		}

		resp, err := fn(r.Context(), req)
		if err != nil {
			writeRPCError(w, http.StatusInternalServerError, err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func writeRPCError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
