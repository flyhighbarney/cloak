package api

import "context"

// Engine is the entry point transports call into.
type Engine interface {
	Handle(ctx context.Context, r *Request) (*Response, error)
}

// Transport is a way requests arrive. HTTP is one; MCP and WebSocket will be
// peers.
type Transport interface {
	Name() string
	APIVersion() string
	Serve(ctx context.Context, engine Engine) error
}
