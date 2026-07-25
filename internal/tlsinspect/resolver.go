package tlsinspect

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Why this file exists (the self-loop bug)
//
// cloakline's whole concept is TRANSPARENT interception: `cloak setup` writes
//
//     127.0.0.1 api.anthropic.com
//
// into the OS hosts file so Claude Code's HTTPS traffic lands on cloakline's
// listener without the user reconfiguring anything. That is the product
// philosophy and we keep it.
//
// The catch: that hosts entry is machine-wide, so it ALSO applies to
// cloakline's own process. When the forward path did
//
//     httpClient.Do("https://api.anthropic.com/...")
//
// the Go resolver honored the hosts file, got 127.0.0.1, and cloakline
// dialed ITSELF. Every forwarded request became an infinite loop, which on
// Windows exhausted the ephemeral TCP port range and produced:
//
//     dial tcp 127.0.0.1:443: connectex: Only one usage of each socket
//     address (protocol/network address/port) is normally permitted.
//
// Fix: resolve the REAL upstream IP ourselves, bypassing the hosts file,
// then dial that IP directly. We use DNS-over-HTTPS to a DNS server addressed
// by IP literal (1.1.1.1 / 8.8.8.8) — an IP literal is never run through the
// hosts file or any name lookup, so the bootstrap query cannot be poisoned by
// our own redirect. DoH over 443 also survives networks that block UDP/53.
// ---------------------------------------------------------------------------

// bootstrapDoHServers are DNS-over-HTTPS endpoints addressed by IP literal.
// Using the raw IP (not a hostname) is deliberate: it guarantees the lookup
// of the DNS server itself never touches the poisoned hosts file. Cloudflare
// and Google both serve certs whose SANs include these IPs, so standard TLS
// verification succeeds with no custom config.
var bootstrapDoHServers = []string{
	"https://1.1.1.1/dns-query",
	"https://8.8.8.8/dns-query",
}

// bootstrapResolver resolves hostnames to IPs while ignoring the OS hosts
// file. Results are cached with the DNS-provided TTL (floored to a sane
// minimum) so we do one DoH round-trip per host per TTL window, not per
// request.
type bootstrapResolver struct {
	client  *http.Client
	servers []string

	mu    sync.Mutex
	cache map[string]cachedAnswer
}

type cachedAnswer struct {
	ip      string
	expires time.Time
}

// newBootstrapResolver builds a resolver. Its internal HTTP client dials the
// DoH servers by IP literal, so it does not itself depend on name resolution
// and cannot loop back through cloakline.
func newBootstrapResolver() *bootstrapResolver {
	return &bootstrapResolver{
		client: &http.Client{
			Timeout: 5 * time.Second,
			// Default transport is fine: the DoH URLs use IP literals, so
			// no hostname lookup occurs when dialing them.
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   3 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          10,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   5 * time.Second,
				ExpectContinueTimeout: time.Second,
			},
		},
		servers: bootstrapDoHServers,
		cache:   make(map[string]cachedAnswer),
	}
}

// resolve returns a real IP for host, bypassing the hosts file. If host is
// already an IP literal it is returned unchanged. A cached answer is used
// when still fresh.
func (b *bootstrapResolver) resolve(ctx context.Context, host string) (string, error) {
	// Already an IP? Nothing to resolve.
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	b.mu.Lock()
	if c, ok := b.cache[host]; ok && time.Now().Before(c.expires) {
		ip := c.ip
		b.mu.Unlock()
		return ip, nil
	}
	b.mu.Unlock()

	ip, ttl, err := b.query(ctx, host)
	if err != nil {
		return "", err
	}

	// Guard against a poisoned answer: if DoH somehow returns loopback (e.g.
	// a hostile local network), refuse it rather than re-creating the very
	// self-loop we exist to prevent.
	if !parseRoutable(ip) {
		return "", fmt.Errorf("bootstrap resolve %s: refusing non-routable answer %q", host, ip)
	}

	if ttl < 30*time.Second {
		ttl = 30 * time.Second
	}
	b.mu.Lock()
	b.cache[host] = cachedAnswer{ip: ip, expires: time.Now().Add(ttl)}
	b.mu.Unlock()
	return ip, nil
}

// parseRoutable reports whether ip is a usable, routable address — i.e. a
// valid IP that is not loopback and not the unspecified address. This is the
// guard that stops a poisoned DNS answer from re-forming the self-loop.
func parseRoutable(ip string) bool {
	pip := net.ParseIP(strings.TrimSpace(ip))
	return pip != nil && !pip.IsLoopback() && !pip.IsUnspecified()
}

// dohResponse is the subset of the RFC 8484 JSON shape we read.
type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Type int    `json:"type"` // 1 = A, 28 = AAAA, 5 = CNAME
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// query performs a DoH A-record lookup against each bootstrap server in turn,
// returning the first routable IPv4 address found and its TTL.
func (b *bootstrapResolver) query(ctx context.Context, host string) (string, time.Duration, error) {
	var lastErr error
	for _, server := range b.servers {
		ip, ttl, err := b.queryOne(ctx, server, host)
		if err == nil {
			return ip, ttl, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no DoH servers configured")
	}
	return "", 0, fmt.Errorf("bootstrap resolve %s: %w", host, lastErr)
}

func (b *bootstrapResolver) queryOne(ctx context.Context, server, host string) (string, time.Duration, error) {
	url := fmt.Sprintf("%s?name=%s&type=A", server, host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := b.client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("%s: status %d", server, resp.StatusCode)
	}

	var out dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, err
	}
	if out.Status != 0 {
		return "", 0, fmt.Errorf("%s: DNS status %d", server, out.Status)
	}
	for _, a := range out.Answer {
		if a.Type != 1 { // want an A record (skip CNAME chains)
			continue
		}
		if net.ParseIP(strings.TrimSpace(a.Data)) != nil {
			return strings.TrimSpace(a.Data), time.Duration(a.TTL) * time.Second, nil
		}
	}
	return "", 0, fmt.Errorf("%s: no A record for %s", server, host)
}

// newPassthroughTransport builds the http.Transport used by the passthrough
// path (non-chat endpoints: auth, token refresh, model listing, telemetry).
// Connection pooling is intentionally disabled — DisableKeepAlives forces a
// fresh TLS handshake per request, eliminating the class of "bad record MAC"
// errors that occur when a pooled connection is reused after the remote peer
// has already closed it. Auth endpoints are infrequent so the extra RTT cost
// is negligible compared to the reliability win.
func newPassthroughTransport(resolver *bootstrapResolver) *http.Transport {
	base := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip, err := resolver.resolve(ctx, host)
			if err != nil {
				return nil, err
			}
			return base.DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// newForwardTransport builds the http.Transport used by the forward path.
// Its DialContext resolves the destination host through the bootstrap
// resolver (hosts-file-free) and dials the resulting real IP, so cloakline
// reaches the genuine upstream instead of looping into its own listener.
func newForwardTransport(resolver *bootstrapResolver) *http.Transport {
	base := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ip, err := resolver.resolve(ctx, host)
			if err != nil {
				return nil, err
			}
			return base.DialContext(ctx, network, net.JoinHostPort(ip, port))
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}
