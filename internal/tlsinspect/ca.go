// Package tlsinspect provides a TLS-terminating inspection layer that
// sits transparently between local CLI tools and their upstream AI
// providers. This is the DLP/SWG (Secure Web Gateway) pattern applied
// specifically to AI traffic on a developer's own machine.
//
// The layer:
//   1. Owns a locally-generated root certificate authority stored on disk.
//   2. Issues leaf certificates on demand for any SNI presented by a client.
//   3. Terminates TLS, runs the request body through the same DLP + injection
//      detectors as the main gateway, and forwards to the real upstream with
//      the client's original authentication headers preserved.
//   4. On the return path, restores tokenized values so the client sees the
//      original text.
//
// The user's subscription auth is never inspected or stored — it passes
// through untouched. Only the request/response body is inspected.
//
// This file: the root CA lifecycle.
package tlsinspect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CA holds the loaded certificate authority.
type CA struct {
	Cert       *x509.Certificate
	Key        *ecdsa.PrivateKey
	CertPEM    []byte // for exporting to the OS trust store
	privateDir string // where the private key lives
}

// LoadOrCreate returns the CA at dir, generating it on first run.
// The dir stores:
//   - ca-cert.pem (public, safe to export)
//   - ca-key.pem  (private, mode 0600)
//   - README.txt  (human-readable explanation)
func LoadOrCreate(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("tlsinspect: mkdir %s: %w", dir, err)
	}
	certPath := filepath.Join(dir, "ca-cert.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")

	if _, err := os.Stat(certPath); err == nil {
		return load(certPath, keyPath, dir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return generate(certPath, keyPath, dir)
}

func generate(certPath, keyPath, dir string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlsinspect: generate CA key: %w", err)
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "policyd local inspection CA",
			Organization: []string{"policyd (local)"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("tlsinspect: create CA cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("tlsinspect: write %s: %w", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("tlsinspect: write %s: %w", keyPath, err)
	}
	writeReadme(dir)

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, CertPEM: certPEM, privateDir: dir}, nil
}

func load(certPath, keyPath, dir string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("tlsinspect: read %s: %w", certPath, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("tlsinspect: %s not PEM", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("tlsinspect: read %s: %w", keyPath, err)
	}
	kblock, _ := pem.Decode(keyPEM)
	if kblock == nil {
		return nil, fmt.Errorf("tlsinspect: %s not PEM", keyPath)
	}
	key, err := x509.ParseECPrivateKey(kblock.Bytes)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, CertPEM: certPEM, privateDir: dir}, nil
}

// ExportedCertPath is the path to the public CA cert (safe to copy elsewhere).
func (c *CA) ExportedCertPath() string {
	return filepath.Join(c.privateDir, "ca-cert.pem")
}

// randSerial returns a 128-bit random serial number.
func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

const readmeText = `This directory contains the local inspection CA for policyd.

WHAT THIS IS
------------
ca-cert.pem is a self-signed root certificate. When installed in your
operating system's trust store, it lets policyd terminate TLS locally so
it can scan the body of your AI-provider requests for PII and secrets
before they leave your machine.

WHAT THIS IS NOT
----------------
This CA is generated on your machine and never leaves it. It is not
trusted by anyone else. It can only issue certificates that are trusted
by the OS accounts on this machine that have explicitly added it to
their trust store.

REVOCATION
----------
To stop trusting this CA:
    policyctl trust remove
or manually remove "policyd local inspection CA" from your OS trust store,
and delete this entire directory.

DO NOT SHARE
------------
ca-key.pem is the private key. Anyone with this file can issue certificates
that your OS will trust. Never copy it off this machine.
`

func writeReadme(dir string) {
	_ = os.WriteFile(filepath.Join(dir, "README.txt"), []byte(readmeText), 0o644)
}
