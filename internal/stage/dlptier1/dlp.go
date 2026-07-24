// Package dlptier1 is the Tier-1 DLP stage: regex + Luhn-checked pattern
// detection over ModText content, with reversible tokenization via
// SessionVault. See docs/architecture.md and docs/threat-model.md.
//
// Tier-1 covers only structured identifiers (SSN, credit-card, email).
// Entropy/secret-pattern detection lands with T-DLP-TIER2.
package dlptier1

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"cloakline/internal/api"
	"cloakline/internal/stage/extracttext"
)

const (
	ID = api.StageID("dlp.tier1")

	SignalFindings api.SignalName = "dlp.tier1.findings"
	SignalWarnings api.SignalName = "dlp.tier1.warnings"
)

// Finding is a single redaction event, either a redaction or a warning.
type Finding struct {
	Kind      api.PIIKind
	Action    api.DLPAction
	Pseudonym api.Pseudonym // populated when Action == Redact or Warn
}

// ActionMap picks the action per finding kind. Kinds not present use Default.
type ActionMap struct {
	Default api.DLPAction
	ByKind  map[api.PIIKind]api.DLPAction
}

// Action returns the resolved action for a kind.
func (a ActionMap) Action(k api.PIIKind) api.DLPAction {
	if v, ok := a.ByKind[k]; ok && v != api.DLPActionUnknown {
		return v
	}
	if a.Default != api.DLPActionUnknown {
		return a.Default
	}
	return api.DLPActionRedact
}

type Stage struct {
	vault   api.SessionVault
	actions ActionMap
}

// New returns a DLP stage. Pass an ActionMap to customize per-kind actions;
// a zero-value map defaults every kind to Redact (backward compatible).
func New(v api.SessionVault, actions ActionMap) *Stage {
	return &Stage{vault: v, actions: actions}
}

func (s *Stage) APIVersion() string         { return api.StageAPIVersion }
func (s *Stage) ID() api.StageID            { return ID }
func (s *Stage) Requires() []api.StageID    { return []api.StageID{extracttext.ID} }
func (s *Stage) Produces() []api.SignalName { return []api.SignalName{SignalFindings} }
func (s *Stage) Modes() api.ModeSet         { return api.ModesOf(api.ModeUnary, api.ModeStreaming) }

func (s *Stage) Run(ctx context.Context, r *api.Request, bus api.SignalBus) error {
	var findings []Finding
	var warnings []Finding
	for mi := range r.Messages {
		for pi := range r.Messages[mi].Parts {
			p := &r.Messages[mi].Parts[pi]
			if p.Modality != api.ModText {
				continue
			}
			mutated, fs, err := s.scan(ctx, r.Session, string(p.Bytes))
			if err != nil {
				return err
			}
			if len(fs) > 0 {
				p.Bytes = []byte(mutated)
				for _, f := range fs {
					if f.Action == api.DLPActionWarn {
						warnings = append(warnings, f)
					} else {
						findings = append(findings, f)
					}
				}
			}
		}
	}
	if err := bus.Set(SignalWarnings, warnings); err != nil {
		return err
	}
	return bus.Set(SignalFindings, findings)
}

// scan applies pattern replacements. Each hit's action is looked up in the
// ActionMap and applied. A Block action short-circuits the whole scan with
// ErrDLPBlocked.
func (s *Stage) scan(ctx context.Context, sid api.SessionID, text string) (string, []Finding, error) {
	var findings []Finding
	out := text

	process := func(pattern *regexp.Regexp, kind api.PIIKind, extraValidate func(string) bool) error {
		action := s.actions.Action(kind)
		if action == api.DLPActionAllow {
			return nil // no scanning needed; pass through
		}
		matches := pattern.FindAllStringIndex(out, -1)
		if matches == nil {
			return nil
		}
		var b strings.Builder
		b.Grow(len(out))
		cursor := 0
		for _, m := range matches {
			raw := out[m[0]:m[1]]
			if extraValidate != nil && !extraValidate(raw) {
				continue
			}
			switch action {
			case api.DLPActionBlock:
				return fmt.Errorf("%w: found %s in content", api.ErrDLPBlocked, kind)
			case api.DLPActionRedact, api.DLPActionWarn:
				pseudonym, err := s.vault.Tokenize(ctx, sid, kind, raw)
				if err != nil {
					return err
				}
				b.WriteString(out[cursor:m[0]])
				b.WriteString(string(pseudonym))
				cursor = m[1]
				findings = append(findings, Finding{Kind: kind, Action: action, Pseudonym: pseudonym})
			}
		}
		b.WriteString(out[cursor:])
		out = b.String()
		return nil
	}

	if err := process(ssnRe, api.PIISSN, nil); err != nil {
		return "", nil, err
	}
	if err := process(ccRe, api.PIICreditCard, isLuhnValid); err != nil {
		return "", nil, err
	}
	if err := process(emailRe, api.PIIEmail, nil); err != nil {
		return "", nil, err
	}

	return out, findings, nil
}

// -------- patterns --------

var (
	ssnRe   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	ccRe    = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)
	emailRe = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b`)
)

// isLuhnValid strips spaces/dashes and applies the Luhn checksum.
func isLuhnValid(raw string) bool {
	digits := make([]int, 0, len(raw))
	for _, r := range raw {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// De-anonymize walks a text and restores pseudonyms → plaintext for the
// return path. Called by the engine for unary responses; the transport
// uses it for streaming chunks.
func DeAnonymize(ctx context.Context, v api.SessionVault, sid api.SessionID, text string) (string, error) {
	if text == "" {
		return "", nil
	}
	// Fast-path check: any bracketed token present?
	if !strings.Contains(text, "[") {
		return text, nil
	}
	matches := pseudonymRe.FindAllStringIndex(text, -1)
	if matches == nil {
		return text, nil
	}
	var b strings.Builder
	b.Grow(len(text))
	cursor := 0
	for _, m := range matches {
		pseud := api.Pseudonym(text[m[0]:m[1]])
		plaintext, err := v.Restore(ctx, sid, pseud)
		if err != nil {
			// Unknown pseudonyms in model output are common (the model may
			// echo a bracketed token that isn't ours). Skip on unknown.
			continue
		}
		b.WriteString(text[cursor:m[0]])
		b.WriteString(plaintext)
		cursor = m[1]
	}
	b.WriteString(text[cursor:])
	return b.String(), nil
}

// pseudonymRe matches our own token shape [KIND_N_rand].
var pseudonymRe = regexp.MustCompile(`\[[A-Z_]+_\d+_[A-Za-z0-9_\-]+\]`)

func init() {
	// Sanity-assert the pattern shape at boot; catches silent regex bugs.
	if !pseudonymRe.MatchString("[SSN_1_ABCdef]") {
		panic(fmt.Sprintf("dlptier1: pseudonymRe self-test failed"))
	}
}
