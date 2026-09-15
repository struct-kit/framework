package codegen

import "fmt"

// RPC generates a minimal internal RPC contract: request/response types,
// a client, and a server handler stub — hand-written Go standing in for
// what a .proto file plus protoc would generate in the framework guide's
// original design (no protoc, no grpc-go available in this build
// environment — see internal/platform/rpc's package doc comment for the
// full deviation note).
func RPC(modulePath, name string) (contractPath, contractSource, clientPath, clientSource, serverPath, serverSource string) {
	pascal := Pascal(name)
	snake := Snake(name)

	contractPath = fmt.Sprintf("internal/rpc/%s/contract.go", snake)
	contractSource = fmt.Sprintf(`package %s

// %sRequest and %sResponse are this call's typed contract — the
// hand-written stand-in for what a .proto file would define. Keep both
// sides (client.go, server.go) built against these same types, so a
// field one side expects and the other doesn't provide is a compile
// error here, the same guarantee protobuf-generated types would give.
type %sRequest struct {
	// TODO: add request fields.
}

type %sResponse struct {
	// TODO: add response fields.
}
`, snake, pascal, pascal, pascal, pascal)

	clientPath = fmt.Sprintf("internal/rpc/%s/client.go", snake)
	clientSource = fmt.Sprintf(`package %s

import (
	"context"

	"%s/internal/platform/rpc"
)

// Client calls the %s service through a resilience-configured
// rpc.Client (retries, circuit breaker, bulkhead, load balancing) —
// build one rpc.Client per downstream service, once at startup, and
// share it across every call.
type Client struct {
	rpc  *rpc.Client
	path string
}

func NewClient(rpcClient *rpc.Client, path string) *Client {
	return &Client{rpc: rpcClient, path: path}
}

// Call is idempotent-marked false by default — flip it to true only
// once you've confirmed this operation is genuinely safe to run more
// than once (framework guide §6.4).
func (c *Client) Call(ctx context.Context, req %sRequest) (%sResponse, error) {
	var resp %sResponse
	err := c.rpc.Call(ctx, "POST", c.path, req, &resp, false)
	return resp, err
}
`, snake, modulePath, pascal, pascal, pascal, pascal)

	serverPath = fmt.Sprintf("internal/rpc/%s/server.go", snake)
	serverSource = fmt.Sprintf(`package %s

import (
	"context"
	"net/http"

	"%s/internal/platform/rpc"
)

// Service is what a real implementation of %s provides — implement
// this against the same request/response types Client uses.
type Service interface {
	Handle%s(ctx context.Context, req %sRequest) (%sResponse, error)
}

// Handler builds the HTTP handler for this call using rpc.Handle's
// generic decode/encode wrapper.
func Handler(svc Service) http.HandlerFunc {
	return rpc.Handle(svc.Handle%s)
}
`, snake, modulePath, pascal, pascal, pascal, pascal, pascal)

	return contractPath, contractSource, clientPath, clientSource, serverPath, serverSource
}
