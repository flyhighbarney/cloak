// Package injection is a rule-based prompt-injection detection stage.
//
// It scores text parts against a curated pattern set. If the sum crosses
// Config.Threshold the stage returns ErrPolicyBlocked. No ML dependency;
// deterministic, fast, tunable.
//
// The rule set is intentionally conservative — high precision, moderate
// recall. Cranking recall is the ONNX classifier's job (deferred behind
// tripwire T-GUARD-INJECT).
package injection

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"cloakline/internal/api"
	"cloakline/internal/stage/extracttext"
)

const (
	ID = api.StageID("injection.rules")

	SignalScore        api.SignalName = "injection.rules.score"
	SignalMatchedRules api.SignalName = "injection.rules.matched"
)

// Config controls the injection detector.
type Config struct {
	Threshold int
	// Extra rules appended to the built-in set. Weights should be 5–50.
	Extra []Rule
}

// Rule is one pattern + weight + a short identifier for audit.
type Rule struct {
	ID     string
	Weight int
	Regex  *regexp.Regexp
}

// Match is a rule hit surfaced as an audit signal.
type Match struct {
	RuleID string
	Weight int
}

type Stage struct {
	cfg   Config
	rules []Rule
}

func New(cfg Config) *Stage {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 50
	}
	rules := BuiltinRules()
	rules = append(rules, cfg.Extra...)
	return &Stage{cfg: cfg, rules: rules}
}

func (s *Stage) APIVersion() string         { return api.StageAPIVersion }
func (s *Stage) ID() api.StageID            { return ID }
func (s *Stage) Requires() []api.StageID    { return []api.StageID{extracttext.ID} }
func (s *Stage) Produces() []api.SignalName { return []api.SignalName{SignalScore, SignalMatchedRules} }
func (s *Stage) Modes() api.ModeSet         { return api.ModesOf(api.ModeUnary, api.ModeStreaming) }

func (s *Stage) Run(ctx context.Context, r *api.Request, bus api.SignalBus) error {
	var total int
	var matched []Match
	for _, m := range r.Messages {
		// Only user and tool-output content is scored. Assistant and system
		// content is our own; scoring it would be self-suspicion.
		if m.Role != api.RoleUser && m.Role != api.RoleTool {
			continue
		}
		for _, p := range m.Parts {
			if p.Modality != api.ModText {
				continue
			}
			lower := strings.ToLower(string(p.Bytes))
			for _, rule := range s.rules {
				if rule.Regex.MatchString(lower) {
					total += rule.Weight
					matched = append(matched, Match{RuleID: rule.ID, Weight: rule.Weight})
				}
			}
		}
	}
	if err := bus.Set(SignalScore, total); err != nil {
		return err
	}
	if err := bus.Set(SignalMatchedRules, matched); err != nil {
		return err
	}
	if total >= s.cfg.Threshold {
		var ids []string
		for _, m := range matched {
			ids = append(ids, m.RuleID)
		}
		return fmt.Errorf("%w: injection score %d >= threshold %d [%s]",
			api.ErrPolicyBlocked, total, s.cfg.Threshold, strings.Join(ids, ","))
	}
	return nil
}

// ScoreResult is the return of Score — total plus which rules matched.
type ScoreResult struct {
	Score   int
	Matches []Match
}

// Score runs `text` against every rule and returns the total plus which
// rules matched. Exposed for callers outside the DAG (the TLS inspection
// module uses this directly for inline scoring without going through the
// full engine).
func Score(text string, rules []Rule) ScoreResult {
	lower := strings.ToLower(text)
	var res ScoreResult
	for _, r := range rules {
		if r.Regex.MatchString(lower) {
			res.Score += r.Weight
			res.Matches = append(res.Matches, Match{RuleID: r.ID, Weight: r.Weight})
		}
	}
	return res
}

// -------- built-in rule set --------

func BuiltinRules() []Rule {
	return []Rule{
		// Direct override attempts — high confidence.
		{ID: "override.ignore_previous", Weight: 50, Regex: regexp.MustCompile(`\b(ignore|disregard|forget)\b[^.!?\n]{0,40}\b(previous|prior|earlier|above|all)\b[^.!?\n]{0,40}\b(instructions?|prompts?|rules?|directives?|context)\b`)},
		{ID: "override.new_instructions", Weight: 40, Regex: regexp.MustCompile(`\b(new|following|updated)\s+instructions?\b[^.!?\n]{0,40}\b(replace|override|supersede)\b`)},
		{ID: "override.role_override", Weight: 40, Regex: regexp.MustCompile(`\byou\s+are\s+(now|actually|really)\s+(a|an|the)?\s*\w+`)},

		// System-prompt exfiltration.
		{ID: "exfil.reveal_system", Weight: 50, Regex: regexp.MustCompile(`\b(reveal|show|print|display|output|repeat|dump)\b[^.!?\n]{0,40}\b(system|initial|hidden|secret|internal)\b[^.!?\n]{0,40}\b(prompts?|instructions?|messages?|rules?)\b`)},
		{ID: "exfil.what_are_your_instructions", Weight: 35, Regex: regexp.MustCompile(`\bwhat\s+(are|were)\s+your\s+(original|initial|system|hidden)\b`)},
		{ID: "exfil.verbatim", Weight: 40, Regex: regexp.MustCompile(`\b(repeat|print)\b[^.!?\n]{0,40}\b(verbatim|word\s*for\s*word|exactly)\b`)},

		// Known jailbreak framing.
		{ID: "jailbreak.dan", Weight: 40, Regex: regexp.MustCompile(`\b(do\s+anything\s+now|dan\s+mode|developer\s+mode|jailbroken?)\b`)},
		{ID: "jailbreak.pretend", Weight: 50, Regex: regexp.MustCompile(`\b(pretend|imagine|roleplay|role-play)\b[^.!?\n]{0,40}\b(no\s+(rules|restrictions|filters|guidelines)|without\s+(rules|restrictions|filters|guidelines))\b`)},
		{ID: "jailbreak.hypothetical_evil", Weight: 30, Regex: regexp.MustCompile(`\b(hypothetical(?:ly)?|for\s+educational\s+purposes)\b[^.!?\n]{0,80}\b(illegal|harmful|dangerous|malicious|weapon|exploit)\b`)},

		// Delimiter smuggling.
		{ID: "delimiter.fake_system", Weight: 35, Regex: regexp.MustCompile(`(<\|(?:system|im_start|start_header_id)\|>|<<sys>>|\[\[system]])`)},
		{ID: "delimiter.role_json", Weight: 30, Regex: regexp.MustCompile(`"role"\s*:\s*"(system|assistant)"`)},

		// Content policy bypass fishing.
		{ID: "bypass.ignore_safety", Weight: 40, Regex: regexp.MustCompile(`\b(ignore|bypass|override|disable)\b[^.!?\n]{0,40}\b(safety|content|ethical|moral)\b[^.!?\n]{0,40}\b(policy|policies|filter|filters|guidelines|rules)\b`)},

		// Suspicious tool coercion.
		{ID: "tool.exfil_call", Weight: 30, Regex: regexp.MustCompile(`\b(send|post|upload|leak|exfiltrate)\b[^.!?\n]{0,30}\b(to|the)\b[^.!?\n]{0,30}\bhttp[s]?://`)},

		// Encoding tricks (indicators only; don't overreach).
		{ID: "encoding.base64_instruction", Weight: 15, Regex: regexp.MustCompile(`\b(decode|base64|rot13)\b[^.!?\n]{0,40}\b(instructions?|prompt|command)\b`)},
	}
}
