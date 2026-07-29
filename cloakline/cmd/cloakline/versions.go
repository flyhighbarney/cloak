package main

import (
	"fmt"

	"cloakline/internal/api"
)

// versionRange enforces `min <= v < maxExclusive`, both major.minor.
type versionRange struct {
	interfaceName string
	min           string
	maxExclusive  string
}

var supported = []versionRange{
	{"Stage", "v1.0", "v2.0"},
	{"Router", "v1.0", "v2.0"},
	{"Upstream", "v1.0", "v2.0"},
	{"Transport", "v1.0", "v2.0"},
	{"SessionVault", "v1.0", "v2.0"},
	{"Extractor", "v1.0", "v2.0"},
	{"Meter", "v1.0", "v2.0"},
	{"PolicyEngine", "v1.0", "v2.0"},
}

func rangeFor(iface string) versionRange {
	for _, r := range supported {
		if r.interfaceName == iface {
			return r
		}
	}
	return versionRange{}
}

// assertVersion panics if the impl's declared APIVersion is outside the range
// supported by this composition root.
func assertVersion(iface, impl, got string) {
	r := rangeFor(iface)
	if r.interfaceName == "" {
		panic(fmt.Sprintf("no version range declared for interface %q", iface))
	}
	if got < r.min || got >= r.maxExclusive {
		panic(fmt.Sprintf("version mismatch: interface=%s impl=%s want %s <= v < %s got %s",
			iface, impl, r.min, r.maxExclusive, got))
	}
}

// assertAll runs every version check needed for this composition root.
func assertAll(stages []api.Stage, router api.Router, ups []api.Upstream,
	transport api.Transport, vault api.SessionVault, meter api.Meter,
	policy api.PolicyEngine) {
	for _, s := range stages {
		assertVersion("Stage", string(s.ID()), s.APIVersion())
	}
	assertVersion("Router", "cel-router", router.APIVersion())
	for _, u := range ups {
		assertVersion("Upstream", string(u.ID()), u.APIVersion())
	}
	assertVersion("Transport", transport.Name(), transport.APIVersion())
	assertVersion("SessionVault", "session", vault.APIVersion())
	assertVersion("Meter", "prometheus", meter.APIVersion())
	assertVersion("PolicyEngine", "cel-go", policy.APIVersion())
}
