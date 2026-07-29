// Package dsl is a beginner-friendly rules language that compiles to the
// existing config primitives (DLP action map, injection threshold, CEL
// routing policy). The audience is a small-firm IT contractor or a
// non-Go developer who wants to write:
//
//     rules:
//       - if: detects ssn
//         then: block
//       - if: injection_score >= 50
//         then: block
//
// The DSL never grows into a full expression language. If a rule can't
// be expressed here, drop into the underlying YAML (pipeline.yaml + CEL)
// or open an issue asking for a new keyword.
package dsl

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"cloakline/internal/api"
)

// File is the on-disk shape of rules.yaml.
type File struct {
	SchemaVersion string      `yaml:"schema_version"`
	Rules         []RawRule   `yaml:"rules"`
}

// RawRule is one entry as it appears on disk, before parsing.
type RawRule struct {
	Name string `yaml:"name,omitempty"`
	If   string `yaml:"if"`
	Then string `yaml:"then"`
}

// Compiled is what the DSL produces: a projection into existing config
// primitives that the composition root can apply.
type Compiled struct {
	// DLPActions overlays onto the pipeline.yaml dlp.actions map.
	// A rule "if: detects <kind> / then: <action>" contributes here.
	DLPActions map[api.PIIKind]api.DLPAction

	// DLPDefault overlays onto pipeline.yaml dlp.default when non-zero.
	DLPDefault api.DLPAction

	// InjectionThreshold overlays onto pipeline.yaml injection.threshold
	// when non-zero. The lowest threshold from any matching rule wins.
	InjectionThreshold int

	// Rules is a human-readable summary useful for the admin dashboard
	// and doctor command.
	Rules []RuleSummary
}

// RuleSummary describes one compiled rule for admin surfaces.
type RuleSummary struct {
	Name     string
	Original string // "if X then Y" as written
	Kind     string // "dlp" | "injection" | "unknown"
	Detail   string
}

// Compile parses raw YAML and produces a Compiled ruleset. Every error
// carries the offending rule so operators can fix at the source.
func Compile(raw []byte) (*Compiled, error) {
	var f File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("%w: parse rules.yaml: %v", api.ErrConfigInvalid, err)
	}
	if f.SchemaVersion != "" && f.SchemaVersion != "v1.0" {
		return nil, fmt.Errorf("%w: rules.yaml schema_version %q; want v1.0",
			api.ErrConfigInvalid, f.SchemaVersion)
	}

	out := &Compiled{
		DLPActions: make(map[api.PIIKind]api.DLPAction),
	}

	for i, rule := range f.Rules {
		if err := out.applyRule(i, rule); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (c *Compiled) applyRule(idx int, r RawRule) error {
	cond := strings.TrimSpace(r.If)
	action := strings.TrimSpace(strings.ToLower(r.Then))
	if cond == "" || action == "" {
		return fmt.Errorf("%w: rule[%d] must have both `if` and `then`", api.ErrConfigInvalid, idx)
	}

	// -------- detects <kind> --------
	if strings.HasPrefix(cond, "detects ") {
		kind := strings.TrimSpace(strings.TrimPrefix(cond, "detects "))
		return c.applyDLPRule(idx, r, kind, action)
	}

	// -------- injection_score >= N --------
	if strings.HasPrefix(cond, "injection_score") {
		return c.applyInjectionRule(idx, r, cond, action)
	}

	return fmt.Errorf("%w: rule[%d] condition %q not recognized. Try: `detects ssn`, `detects any_pii`, `injection_score >= 50`",
		api.ErrConfigInvalid, idx, cond)
}

func (c *Compiled) applyDLPRule(idx int, r RawRule, kind, action string) error {
	act := api.ParseDLPAction(action)
	if act == api.DLPActionUnknown {
		return fmt.Errorf("%w: rule[%d] then %q; want allow|warn|redact|block",
			api.ErrConfigInvalid, idx, action)
	}
	summary := RuleSummary{
		Name:     r.Name,
		Original: fmt.Sprintf("if: %s / then: %s", r.If, r.Then),
		Kind:     "dlp",
	}
	if kind == "any_pii" || kind == "any" {
		c.DLPDefault = act
		summary.Detail = fmt.Sprintf("DLP default = %s", act)
	} else {
		piiKind := api.PIIKind(kind)
		if !isKnownKind(piiKind) {
			return fmt.Errorf("%w: rule[%d] unknown detection kind %q. Known: ssn, credit_card, email, phone, person_name, api_key, private_key, github_token, aws_key, password, ip_address, url_path, or any_pii",
				api.ErrConfigInvalid, idx, kind)
		}
		c.DLPActions[piiKind] = act
		summary.Detail = fmt.Sprintf("%s → %s", kind, act)
	}
	c.Rules = append(c.Rules, summary)
	return nil
}

func (c *Compiled) applyInjectionRule(idx int, r RawRule, cond, action string) error {
	// Accept: injection_score >= N, injection_score > N.
	rest := strings.TrimSpace(strings.TrimPrefix(cond, "injection_score"))
	var threshold int
	switch {
	case strings.HasPrefix(rest, ">="):
		n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(rest, ">=")))
		if err != nil {
			return fmt.Errorf("%w: rule[%d] injection_score threshold must be an integer: %v",
				api.ErrConfigInvalid, idx, err)
		}
		threshold = n
	case strings.HasPrefix(rest, ">"):
		n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(rest, ">")))
		if err != nil {
			return fmt.Errorf("%w: rule[%d] injection_score threshold must be an integer: %v",
				api.ErrConfigInvalid, idx, err)
		}
		threshold = n + 1
	default:
		return fmt.Errorf("%w: rule[%d] injection_score condition needs >= or >: %q",
			api.ErrConfigInvalid, idx, cond)
	}
	if action != "block" {
		return fmt.Errorf("%w: rule[%d] injection_score rules currently only support `then: block`",
			api.ErrConfigInvalid, idx)
	}
	// The lowest threshold across all rules wins (most protective).
	if c.InjectionThreshold == 0 || threshold < c.InjectionThreshold {
		c.InjectionThreshold = threshold
	}
	c.Rules = append(c.Rules, RuleSummary{
		Name:     r.Name,
		Original: fmt.Sprintf("if: %s / then: %s", r.If, r.Then),
		Kind:     "injection",
		Detail:   fmt.Sprintf("threshold ≥ %d → block", threshold),
	})
	return nil
}

func isKnownKind(k api.PIIKind) bool {
	switch k {
	case api.PIISSN, api.PIICreditCard, api.PIIEmail, api.PIIPhone,
		api.PIIPersonName, api.PIIAPIKey, api.PIIPrivateKey,
		api.PIIGitHubToken, api.PIIAWSKey, api.PIIPassword,
		api.PIIIPAddress, api.PIIURLPath:
		return true
	}
	return false
}

// Merge applies a Compiled overlay onto existing DLP/injection settings.
// Explicit overrides in the DSL take precedence over pipeline.yaml.
func Merge(dlpActions map[api.PIIKind]api.DLPAction, dlpDefault api.DLPAction, injectionThreshold int, c *Compiled) (map[api.PIIKind]api.DLPAction, api.DLPAction, int) {
	if c == nil {
		return dlpActions, dlpDefault, injectionThreshold
	}
	out := make(map[api.PIIKind]api.DLPAction, len(dlpActions)+len(c.DLPActions))
	for k, v := range dlpActions {
		out[k] = v
	}
	for k, v := range c.DLPActions {
		out[k] = v // DSL wins
	}
	if c.DLPDefault != api.DLPActionUnknown {
		dlpDefault = c.DLPDefault
	}
	if c.InjectionThreshold > 0 {
		injectionThreshold = c.InjectionThreshold
	}
	return out, dlpDefault, injectionThreshold
}

// ErrEmpty is returned by Compile when rules.yaml has zero rules — not
// an error per se, but useful for the loader to distinguish.
var ErrEmpty = errors.New("rules.yaml has no rules")
