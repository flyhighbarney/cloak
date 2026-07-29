package api

import "context"

// VaultState is the state machine value for a session vault.
type VaultState uint8

const (
	VaultUnknown   VaultState = 0
	VaultOpen      VaultState = 1
	VaultStreaming VaultState = 2
	VaultDraining  VaultState = 3
	VaultClosed    VaultState = 4
	VaultFailed    VaultState = 5
)

func (v VaultState) String() string {
	switch v {
	case VaultOpen:
		return "open"
	case VaultStreaming:
		return "streaming"
	case VaultDraining:
		return "draining"
	case VaultClosed:
		return "closed"
	case VaultFailed:
		return "failed"
	}
	return "unknown"
}

// Outcome is the terminal state class for a session.
type Outcome uint8

const (
	OutcomeUnknown       Outcome = 0
	OutcomeSuccess       Outcome = 1
	OutcomeClientError   Outcome = 2
	OutcomePolicyBlocked Outcome = 3
	OutcomeUpstreamError Outcome = 4
	OutcomeTimeout       Outcome = 5
	OutcomePanic         Outcome = 6
	OutcomeStreamAborted Outcome = 7
)

// Known PII kinds. Adding a kind is a minor bump.
const (
	PIISSN         PIIKind = "ssn"
	PIICreditCard  PIIKind = "credit_card"
	PIIEmail       PIIKind = "email"
	PIIPhone       PIIKind = "phone"
	PIIPersonName  PIIKind = "person_name"
	PIIAPIKey      PIIKind = "api_key"
	PIIPrivateKey  PIIKind = "private_key"
	PIIGitHubToken PIIKind = "github_token"
	PIIAWSKey      PIIKind = "aws_key"
	PIIPassword    PIIKind = "password"
	PIIIPAddress   PIIKind = "ip_address"
	PIIURLPath     PIIKind = "url_path"
)

// SessionVault is a stream-scoped state machine mapping PII → pseudonyms.
// See docs/interface-contracts.md and docs/threat-model.md T5.
type SessionVault interface {
	APIVersion() string
	Begin(ctx context.Context, sid SessionID) error
	Tokenize(ctx context.Context, sid SessionID, kind PIIKind, plaintext string) (Pseudonym, error)
	Restore(ctx context.Context, sid SessionID, p Pseudonym) (string, error)
	Transition(ctx context.Context, sid SessionID, to VaultState) error
	State(sid SessionID) VaultState
	Close(ctx context.Context, sid SessionID, outcome Outcome) error
}
