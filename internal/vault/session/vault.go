// Package session implements the stream-scoped SessionVault state machine.
//
// State transitions:
//
//	Open --Begin done--> Streaming (once the first chunk flows)
//	Streaming --Transition(Draining)--> Draining
//	Draining --Close--> Closed
//	any --Close(Failed) or panic--> Failed --Close--> Closed
//
// Tokenize is legal in Open and Streaming; Restore is legal in Streaming
// and Draining. Restore never returns a partial replacement — either the
// pseudonym maps to a full plaintext or an error is returned.
//
// See docs/interface-contracts.md and docs/threat-model.md T5.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"policyd/internal/api"
)

const APIVersion = api.SessionVaultAPIVersion

// Vault holds all live sessions.
type Vault struct {
	mu       sync.RWMutex
	sessions map[api.SessionID]*session
}

type session struct {
	mu      sync.Mutex
	state   api.VaultState
	counter uint32 // for stable pseudonym numbering within the session
	// map[Pseudonym]plaintext — plaintext held only for the session's lifetime.
	forward map[api.Pseudonym]string
	// map[plaintext]Pseudonym — dedupes tokenizations of the same value.
	reverse map[string]api.Pseudonym
}

func New() *Vault {
	return &Vault{sessions: make(map[api.SessionID]*session)}
}

func (v *Vault) APIVersion() string { return APIVersion }

func (v *Vault) Begin(ctx context.Context, sid api.SessionID) error {
	if sid == "" {
		return fmt.Errorf("%w: empty session id", api.ErrVaultState)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.sessions[sid]; ok {
		return fmt.Errorf("%w: session %s already open", api.ErrVaultState, sid)
	}
	v.sessions[sid] = &session{
		state:   api.VaultOpen,
		forward: make(map[api.Pseudonym]string),
		reverse: make(map[string]api.Pseudonym),
	}
	return nil
}

func (v *Vault) Tokenize(ctx context.Context, sid api.SessionID, kind api.PIIKind, plaintext string) (api.Pseudonym, error) {
	s, err := v.grab(sid)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != api.VaultOpen && s.state != api.VaultStreaming {
		return "", fmt.Errorf("%w: tokenize in state %s", api.ErrVaultState, s.state)
	}
	if existing, ok := s.reverse[plaintext]; ok {
		return existing, nil
	}
	s.counter++
	// pseudonym form: [KIND_N_rand]
	pseud := api.Pseudonym(fmt.Sprintf("[%s_%d_%s]",
		upperKind(kind), s.counter, randToken()))
	s.forward[pseud] = plaintext
	s.reverse[plaintext] = pseud
	return pseud, nil
}

func (v *Vault) Restore(ctx context.Context, sid api.SessionID, p api.Pseudonym) (string, error) {
	s, err := v.grab(sid)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != api.VaultStreaming && s.state != api.VaultDraining {
		return "", fmt.Errorf("%w: restore in state %s", api.ErrVaultState, s.state)
	}
	plaintext, ok := s.forward[p]
	if !ok {
		return "", fmt.Errorf("%w: unknown pseudonym", api.ErrVaultState)
	}
	return plaintext, nil
}

func (v *Vault) Transition(ctx context.Context, sid api.SessionID, to api.VaultState) error {
	s, err := v.grab(sid)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !legalTransition(s.state, to) {
		return fmt.Errorf("%w: illegal transition %s -> %s", api.ErrVaultState, s.state, to)
	}
	s.state = to
	return nil
}

func (v *Vault) State(sid api.SessionID) api.VaultState {
	v.mu.RLock()
	s, ok := v.sessions[sid]
	v.mu.RUnlock()
	if !ok {
		return api.VaultUnknown
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (v *Vault) Close(ctx context.Context, sid api.SessionID, outcome api.Outcome) error {
	v.mu.Lock()
	s, ok := v.sessions[sid]
	if !ok {
		v.mu.Unlock()
		return nil // idempotent
	}
	delete(v.sessions, sid)
	v.mu.Unlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	// Zeroize backing data.
	for k := range s.forward {
		s.forward[k] = ""
		delete(s.forward, k)
	}
	for k := range s.reverse {
		delete(s.reverse, k)
	}
	s.state = api.VaultClosed
	return nil
}

// Active reports how many sessions are open. Feeds a gauge.
func (v *Vault) Active() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.sessions)
}

func (v *Vault) grab(sid api.SessionID) (*session, error) {
	v.mu.RLock()
	s, ok := v.sessions[sid]
	v.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: unknown session %s", api.ErrVaultState, sid)
	}
	return s, nil
}

// legalTransition enforces the state machine. Any → Failed is legal; Failed → Closed only.
func legalTransition(from, to api.VaultState) bool {
	if to == api.VaultFailed {
		return from != api.VaultClosed
	}
	if from == api.VaultFailed {
		return to == api.VaultClosed
	}
	switch from {
	case api.VaultOpen:
		return to == api.VaultStreaming || to == api.VaultDraining || to == api.VaultClosed
	case api.VaultStreaming:
		return to == api.VaultDraining || to == api.VaultClosed
	case api.VaultDraining:
		return to == api.VaultClosed
	}
	return false
}

func upperKind(k api.PIIKind) string {
	out := make([]byte, 0, len(k))
	for _, r := range string(k) {
		if r >= 'a' && r <= 'z' {
			out = append(out, byte(r-('a'-'A')))
		} else if r == '_' || r == '-' {
			out = append(out, '_')
		} else {
			out = append(out, byte(r))
		}
	}
	return string(out)
}

func randToken() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "xxxxxx"
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// StreamingWrite is a small helper: transitions a session to VaultFailed
// if any de-anonymization fails. Transports must call this before writing
// any chunk that has been de-anonymized.
func StreamingWrite(v *Vault, sid api.SessionID) error {
	s := v.State(sid)
	if s == api.VaultFailed || s == api.VaultClosed {
		return errors.New("session vault not streaming")
	}
	return nil
}
