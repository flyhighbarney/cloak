// Package api holds the canonical types and interface contracts for policyd.
//
// This package MUST NOT import any other package in this module. It is a leaf.
// If a change here would force an import from a lower package, the design is wrong.
//
// See docs/interface-contracts.md for rationale.
package api

// APIVersion strings for interfaces defined in this package.
// Composition root enforces compatibility ranges at boot.
const (
	StageAPIVersion        = "v1.0"
	RouterAPIVersion       = "v1.0"
	UpstreamAPIVersion     = "v1.0"
	TransportAPIVersion    = "v1.0"
	SessionVaultAPIVersion = "v1.0"
	ExtractorAPIVersion    = "v1.0"
	MeterAPIVersion        = "v1.0"
	PolicyEngineAPIVersion = "v1.0"
)
