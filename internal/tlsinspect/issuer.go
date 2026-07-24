package tlsinspect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Issuer produces leaf certificates on demand for any SNI presented by
// a client. Issued certs are cached in memory for the process lifetime.
type Issuer struct {
	ca    *CA
	mu    sync.RWMutex
	cache map[string]*tls.Certificate
}

// NewIssuer wraps a CA in a per-SNI issuer.
func NewIssuer(ca *CA) *Issuer {
	return &Issuer{ca: ca, cache: make(map[string]*tls.Certificate, 32)}
}

// GetCertificate is a drop-in for tls.Config.GetCertificate. It reads the
// SNI hostname from hello and returns (issuing if necessary) a leaf.
func (i *Issuer) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := normalizeSNI(hello.ServerName)
	if host == "" {
		// Fallback: use the local IP the client dialed. Most clients set SNI,
		// so this branch is defensive.
		host = "localhost"
	}
	i.mu.RLock()
	if c, ok := i.cache[host]; ok {
		i.mu.RUnlock()
		return c, nil
	}
	i.mu.RUnlock()

	i.mu.Lock()
	defer i.mu.Unlock()
	// Double-check after acquiring the write lock.
	if c, ok := i.cache[host]; ok {
		return c, nil
	}
	c, err := i.issue(host)
	if err != nil {
		return nil, err
	}
	i.cache[host] = c
	return c, nil
}

// issue creates a fresh leaf cert for a hostname or IP.
func (i *Issuer) issue(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"cloakline (local inspection leaf)"},
		},
		NotBefore:   now.Add(-1 * time.Hour),
		NotAfter:    now.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, i.ca.Cert, &key.PublicKey, i.ca.Key)
	if err != nil {
		return nil, fmt.Errorf("tlsinspect: issue leaf for %s: %w", host, err)
	}
	// Bundle: leaf + CA so clients that don't have our CA still see the chain.
	return &tls.Certificate{
		Certificate: [][]byte{leafDER, i.ca.Cert.Raw},
		PrivateKey:  key,
		Leaf:        mustParse(leafDER),
	}, nil
}

func mustParse(der []byte) *x509.Certificate {
	c, _ := x509.ParseCertificate(der)
	return c
}

func normalizeSNI(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	// Strip trailing dot if present ("api.openai.com.").
	s = strings.TrimSuffix(s, ".")
	return s
}
