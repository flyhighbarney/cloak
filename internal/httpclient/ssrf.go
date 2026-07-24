// Package httpclient provides an SSRF-hardened *http.Client.
//
// The client enforces:
//   - Scheme allowlist (https by default; http only for explicitly-declared
//     loopback local-model upstreams).
//   - Resolve DNS once per dial; validate the resolved IP against the policy;
//     dial the resolved IP (pinned for the connection). Blocks DNS rebinding.
//   - Post-resolve IP block: RFC1918, link-local, CGNAT, loopback, multicast,
//     broadcast, and IPv6 equivalents — unless whitelisted by upstream config.
//   - Refuses cross-host redirects; max 3 same-host redirects.
//
// See docs/threat-model.md T1 for the threats this defends against.
package httpclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"policyd/internal/api"
)

// Policy controls what dials are permitted.
// Zero value denies everything — callers must build a Policy explicitly.
type Policy struct {
	// AllowSchemes lists permitted URL schemes. Typically {"https"} in prod,
	// {"https", "http"} for a config that declares local-model upstreams.
	AllowSchemes []string

	// AllowedHosts is a set of hosts (as written in URLs) permitted regardless
	// of resolved IP. Use for cloud provider hostnames like "api.openai.com".
	AllowedHosts map[string]struct{}

	// AllowLoopback permits dials to 127.0.0.0/8 and ::1. Only true when at
	// least one upstream is declared as a local model.
	AllowLoopback bool

	// AllowPrivate permits dials to RFC1918 space. Only true when explicitly
	// requested — most deployments do not need this.
	AllowPrivate bool

	// DialTimeout bounds the TCP handshake.
	DialTimeout time.Duration

	// RequestTimeout bounds the entire request. Zero = no timeout (streaming).
	RequestTimeout time.Duration
}

// StrictPolicy returns a Policy suitable for production cloud-only workloads.
func StrictPolicy(cloudHosts ...string) Policy {
	hosts := make(map[string]struct{}, len(cloudHosts))
	for _, h := range cloudHosts {
		hosts[strings.ToLower(h)] = struct{}{}
	}
	return Policy{
		AllowSchemes:   []string{"https"},
		AllowedHosts:   hosts,
		DialTimeout:    5 * time.Second,
		RequestTimeout: 30 * time.Second,
	}
}

// New returns a new *http.Client wired to enforce the policy.
func New(p Policy) *http.Client {
	dialer := &net.Dialer{
		Timeout:   p.DialTimeout,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return safeDial(ctx, dialer, p, network, addr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// Disable proxy discovery — no CONNECT via env.
		Proxy: nil,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   p.RequestTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("%w: too many redirects", api.ErrSSRFBlocked)
			}
			// Same-host only.
			if req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("%w: cross-host redirect from %s to %s",
					api.ErrSSRFBlocked, via[0].URL.Host, req.URL.Host)
			}
			return nil
		},
	}
}

// ValidateURL checks a URL against the policy without performing a dial.
// Callers should invoke this at config load time.
func ValidateURL(p Policy, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: parse %q: %v", api.ErrSSRFBlocked, raw, err)
	}
	return validateScheme(p, u)
}

func validateScheme(p Policy, u *url.URL) error {
	if u.Scheme == "" {
		return fmt.Errorf("%w: missing scheme", api.ErrSSRFBlocked)
	}
	for _, s := range p.AllowSchemes {
		if strings.EqualFold(s, u.Scheme) {
			return nil
		}
	}
	return fmt.Errorf("%w: scheme %q not in allowlist", api.ErrSSRFBlocked, u.Scheme)
}

func safeDial(ctx context.Context, dialer *net.Dialer, p Policy, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: split host/port %q: %v", api.ErrSSRFBlocked, addr, err)
	}

	// Fast path for allowed hosts by name (still resolve to validate IP).
	_, hostAllowed := p.AllowedHosts[strings.ToLower(host)]

	// If the "host" is already a literal IP, validate directly.
	if ip := net.ParseIP(host); ip != nil {
		if !ipAllowed(p, ip, hostAllowed) {
			return nil, fmt.Errorf("%w: dial to blocked IP %s", api.ErrSSRFBlocked, ip)
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}

	// Resolve DNS once. Pin the first allowed IP.
	resolver := net.DefaultResolver
	ips, err := resolver.LookupIP(ctx, ipNet(network), host)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve %q: %v", api.ErrSSRFBlocked, host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no addresses for %q", api.ErrSSRFBlocked, host)
	}

	for _, ip := range ips {
		if !ipAllowed(p, ip, hostAllowed) {
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		// Try next IP.
	}
	return nil, fmt.Errorf("%w: no permitted IP for %q", api.ErrSSRFBlocked, host)
}

func ipNet(network string) string {
	switch network {
	case "tcp4", "udp4":
		return "ip4"
	case "tcp6", "udp6":
		return "ip6"
	}
	return "ip"
}

// ipAllowed returns whether an IP may be dialed under the given policy.
// hostAllowed is true if the ORIGINAL hostname was on the allowlist —
// but we still refuse metadata endpoints and clearly-private space
// so a hijacked or misconfigured DNS entry cannot open a hole.
func ipAllowed(p Policy, ip net.IP, hostAllowed bool) bool {
	if ip == nil {
		return false
	}

	// Absolute blocks regardless of any allowlist:
	if isLinkLocal(ip) {
		return false // AWS/GCP/Azure metadata endpoints are link-local
	}
	if ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	if isBroadcast(ip) {
		return false
	}
	// Deliberately not calling ip.IsPrivate() as the only gate — see below.

	// Loopback: only if policy permits it.
	if ip.IsLoopback() {
		return p.AllowLoopback
	}

	// RFC1918 / CGNAT: policy-gated.
	if isPrivate(ip) {
		return p.AllowPrivate
	}

	// If the original hostname was on the allowlist, and the IP is public,
	// permit. This is the intended cloud-provider path.
	if hostAllowed {
		return true
	}

	// Public IP but hostname not on the allowlist: deny.
	return false
}

func isLinkLocal(ip net.IP) bool {
	// IPv4: 169.254.0.0/16
	if v4 := ip.To4(); v4 != nil {
		return v4[0] == 169 && v4[1] == 254
	}
	// IPv6: fe80::/10
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func isBroadcast(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		return v4.Equal(net.IPv4bcast)
	}
	return false
}

func isPrivate(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		// 10.0.0.0/8
		if v4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if v4[0] == 192 && v4[1] == 168 {
			return true
		}
		// 100.64.0.0/10 CGNAT
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return true
		}
		return false
	}
	// IPv6 ULA fc00::/7
	return ip[0]&0xfe == 0xfc
}

// ErrBlockedIP is returned in errors surfaced through the dial path.
var ErrBlockedIP = errors.New("blocked destination IP")
