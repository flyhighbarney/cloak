package httpclient

import (
	"errors"
	"net"
	"testing"

	"cloakline/internal/api"
)

func TestValidateURL_SchemeAllowlist(t *testing.T) {
	p := StrictPolicy("api.openai.com")
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"https://api.openai.com/v1/chat/completions", false},
		{"http://api.openai.com/", true},
		{"ftp://api.openai.com/", true},
	}
	for _, c := range cases {
		err := ValidateURL(p, c.url)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidateURL(%q) err=%v wantErr=%v", c.url, err, c.wantErr)
		}
		if c.wantErr && err != nil && !errors.Is(err, api.ErrSSRFBlocked) {
			t.Errorf("ValidateURL(%q) err %v is not ErrSSRFBlocked", c.url, err)
		}
	}
}

func TestIPAllowed_LinkLocal(t *testing.T) {
	p := Policy{AllowSchemes: []string{"https"}, AllowedHosts: map[string]struct{}{"attacker.com": {}}}
	// AWS metadata endpoint. hostAllowed=true; must still refuse.
	got := ipAllowed(p, net.ParseIP("169.254.169.254"), true)
	if got {
		t.Fatal("link-local IP must be refused even when hostname is allowlisted")
	}
	// GCP metadata endpoint IPv4.
	if ipAllowed(p, net.ParseIP("169.254.169.254"), false) {
		t.Fatal("link-local IP must be refused")
	}
}

func TestIPAllowed_Loopback(t *testing.T) {
	deny := Policy{AllowSchemes: []string{"https"}}
	allow := Policy{AllowSchemes: []string{"http"}, AllowLoopback: true}
	if ipAllowed(deny, net.ParseIP("127.0.0.1"), true) {
		t.Fatal("loopback must be refused without AllowLoopback")
	}
	if !ipAllowed(allow, net.ParseIP("127.0.0.1"), true) {
		t.Fatal("loopback must be permitted with AllowLoopback")
	}
	if ipAllowed(deny, net.ParseIP("::1"), true) {
		t.Fatal("IPv6 loopback must be refused without AllowLoopback")
	}
}

func TestIPAllowed_Private(t *testing.T) {
	p := Policy{AllowSchemes: []string{"https"}, AllowedHosts: map[string]struct{}{"internal.corp": {}}}
	// RFC1918 blocks
	private := []string{"10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.254", "192.168.1.1", "100.64.0.1"}
	for _, ipStr := range private {
		if ipAllowed(p, net.ParseIP(ipStr), true) {
			t.Errorf("private IP %s must be refused without AllowPrivate", ipStr)
		}
	}
	pAllow := p
	pAllow.AllowPrivate = true
	for _, ipStr := range private {
		if !ipAllowed(pAllow, net.ParseIP(ipStr), true) {
			t.Errorf("private IP %s must be permitted with AllowPrivate", ipStr)
		}
	}
}

func TestIPAllowed_Public(t *testing.T) {
	p := Policy{AllowSchemes: []string{"https"}, AllowedHosts: map[string]struct{}{"api.openai.com": {}}}
	if !ipAllowed(p, net.ParseIP("104.18.7.192"), true) {
		t.Fatal("public IP with allowlisted host must be permitted")
	}
	if ipAllowed(p, net.ParseIP("104.18.7.192"), false) {
		t.Fatal("public IP without allowlisted host must be refused")
	}
}

func TestIPAllowed_Multicast(t *testing.T) {
	p := Policy{AllowedHosts: map[string]struct{}{"anything": {}}, AllowLoopback: true, AllowPrivate: true}
	if ipAllowed(p, net.ParseIP("224.0.0.1"), true) {
		t.Fatal("multicast must be refused")
	}
	if ipAllowed(p, net.ParseIP("ff02::1"), true) {
		t.Fatal("IPv6 multicast must be refused")
	}
}

func TestIPAllowed_Unspecified(t *testing.T) {
	p := Policy{AllowedHosts: map[string]struct{}{"anything": {}}, AllowLoopback: true, AllowPrivate: true}
	if ipAllowed(p, net.ParseIP("0.0.0.0"), true) {
		t.Fatal("0.0.0.0 must be refused")
	}
	if ipAllowed(p, net.ParseIP("::"), true) {
		t.Fatal(":: must be refused")
	}
}
