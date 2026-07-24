package api

import "errors"

// Sentinel errors. All returns from api-satisfying implementations must
// wrap one of these with fmt.Errorf("...: %w", err, ErrX). Callers use errors.Is.
var (
	ErrRateLimit       = errors.New("upstream rate limited")
	ErrUnavailable     = errors.New("upstream unavailable")
	ErrClientAbort     = errors.New("client aborted request")
	ErrProvider        = errors.New("provider error")
	ErrPolicyBlocked   = errors.New("blocked by policy")
	ErrBudgetExceeded  = errors.New("budget exceeded")
	ErrCapMismatch     = errors.New("no upstream matches required capabilities")
	ErrDLPRedaction    = errors.New("DLP rejected content")
	ErrDLPBlocked      = errors.New("DLP blocked content")
	ErrVaultState      = errors.New("vault state machine violation")
	ErrVersionMismatch = errors.New("component API version incompatible")
	ErrConfigInvalid   = errors.New("invalid configuration")
	ErrAuthFailed      = errors.New("authentication failed")
	ErrSSRFBlocked     = errors.New("outbound request blocked by SSRF policy")
)
