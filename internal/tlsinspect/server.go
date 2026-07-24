package tlsinspect

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"time"

	"cloakline/internal/obs/log"
)

// Config controls the inspection server behavior.
type Config struct {
	// Listen is the TLS listen address (":8443" typical).
	Listen string
	// Hosts is the set of hostnames the server will inspect. Requests
	// whose SNI/Host isn't in this set are refused. This keeps the
	// scope narrow: only AI provider hostnames.
	Hosts []string
	// StageTimeout bounds DLP + injection scanning.
	StageTimeout time.Duration
	// ForwardTimeout bounds the outbound (real) request.
	ForwardTimeout time.Duration
}

// Server terminates TLS with per-SNI certs and forwards each request
// through the inspection pipeline to its real upstream host.
type Server struct {
	cfg     Config
	issuer  *Issuer
	handler *Handler
	logger  *log.Logger
}

// NewServer wires the pieces. Panic-free — bad config returns an error.
func NewServer(cfg Config, ca *CA, handler *Handler, logger *log.Logger) (*Server, error) {
	if cfg.Listen == "" {
		return nil, errors.New("tlsinspect: Listen must be set")
	}
	if len(cfg.Hosts) == 0 {
		return nil, errors.New("tlsinspect: at least one Host must be configured")
	}
	if cfg.StageTimeout == 0 {
		cfg.StageTimeout = 10 * time.Second
	}
	if cfg.ForwardTimeout == 0 {
		cfg.ForwardTimeout = 120 * time.Second
	}
	return &Server{
		cfg:     cfg,
		issuer:  NewIssuer(ca),
		handler: handler,
		logger:  logger,
	}, nil
}

// Serve blocks until ctx is cancelled or the listener errors.
func (s *Server) Serve(ctx context.Context) error {
	tlsCfg := &tls.Config{
		GetCertificate: s.issuer.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", s.cfg.Listen, tlsCfg)
	if err != nil {
		return fmt.Errorf("tlsinspect: listen %s: %w", s.cfg.Listen, err)
	}
	defer ln.Close()

	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       s.cfg.ForwardTimeout,
		WriteTimeout:      s.cfg.ForwardTimeout,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	s.logger.Info("tlsinspect.listening", log.Fields{
		"addr":  s.cfg.Listen,
		"hosts": s.cfg.Hosts,
	})
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// ServeHTTP dispatches every terminated connection.
//
// Automatic failsafe: the whole per-request pipeline runs under a recover().
// If any stage panics (a malformed body, a nil deref in a new rule, whatever),
// the process must NOT die — a dead listener means the hosts-file redirect
// points at a dead port and every AI client on the machine breaks. Instead we
// FAIL OPEN: replay the untouched request to the real upstream so the user's
// request still succeeds. The user never has to know or intervene.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	if !s.allowed(host) {
		s.logger.Warn("tlsinspect.host_not_allowed", log.Fields{"host": host})
		http.Error(w, `{"error":"host not configured for inspection"}`, http.StatusMisdirectedRequest)
		return
	}

	serveWithFailsafe(
		w, r, host,
		s.handler.MaxBodyBytes(),
		s.logger,
		s.handler.Handle,
		s.handler.FailOpen,
	)
}

// serveWithFailsafe runs the inspection pipeline under an automatic failsafe.
// It buffers the request body, invokes handle, and — if handle panics before
// writing a response — recovers and replays the untouched request via failOpen
// so the caller still succeeds. Extracted from ServeHTTP so the failsafe can
// be unit-tested with fakes and without hitting the network.
//
// Contract:
//   - A panic in handle NEVER escapes (the daemon survives).
//   - If nothing was written yet, failOpen runs (fail open to upstream).
//   - If handle already started writing, we only log — a partial response
//     can't be retried, but the process stays up.
func serveWithFailsafe(
	w http.ResponseWriter,
	r *http.Request,
	host string,
	bodyCap int64,
	logger *log.Logger,
	handle func(http.ResponseWriter, *http.Request, string),
	failOpen func(http.ResponseWriter, *http.Request, string, []byte),
) {
	body, err := io.ReadAll(io.LimitReader(r.Body, bodyCap+1))
	if err != nil {
		http.Error(w, `{"error":"read body failed"}`, http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	tw := &trackedWriter{ResponseWriter: w}

	defer func() {
		if rec := recover(); rec != nil {
			if logger != nil {
				logger.Error("tlsinspect.panic_recovered", log.Fields{
					"host":  host,
					"panic": fmt.Sprintf("%v", rec),
					"stack": string(debug.Stack()),
				})
			}
			if tw.wrote {
				return // partial response already sent; daemon still alive
			}
			failOpen(tw, r, host, body)
		}
	}()

	handle(tw, r, host)
}

// trackedWriter notes whether a response has started, so the failsafe knows
// whether it's still safe to replay the request.
type trackedWriter struct {
	http.ResponseWriter
	wrote bool
}

func (t *trackedWriter) WriteHeader(code int) {
	t.wrote = true
	t.ResponseWriter.WriteHeader(code)
}

func (t *trackedWriter) Write(p []byte) (int, error) {
	t.wrote = true
	return t.ResponseWriter.Write(p)
}

func (s *Server) allowed(host string) bool {
	for _, h := range s.cfg.Hosts {
		if host == h {
			return true
		}
	}
	return false
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}
