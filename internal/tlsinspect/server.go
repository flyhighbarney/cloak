package tlsinspect

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"policyd/internal/obs/log"
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
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := hostOnly(r.Host)
	if !s.allowed(host) {
		s.logger.Warn("tlsinspect.host_not_allowed", log.Fields{"host": host})
		http.Error(w, `{"error":"host not configured for inspection"}`, http.StatusMisdirectedRequest)
		return
	}
	// Delegate the substantive work to the Handler (see forward.go).
	s.handler.Handle(w, r, host)
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
