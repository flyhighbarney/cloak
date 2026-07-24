package dsl

import (
	"errors"
	"strings"
	"testing"

	"cloakline/internal/api"
)

func TestCompileValidRules(t *testing.T) {
	src := []byte(`
schema_version: v1.0
rules:
  - name: Block SSNs
    if: detects ssn
    then: block
  - name: Redact emails
    if: detects email
    then: redact
  - name: Warn on unknown API keys
    if: detects api_key
    then: warn
  - name: Any other PII stays redacted
    if: detects any_pii
    then: redact
  - name: Block obvious injections
    if: injection_score >= 50
    then: block
`)
	c, err := Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if c.DLPActions[api.PIISSN] != api.DLPActionBlock {
		t.Errorf("ssn should be block, got %v", c.DLPActions[api.PIISSN])
	}
	if c.DLPActions[api.PIIEmail] != api.DLPActionRedact {
		t.Errorf("email should be redact, got %v", c.DLPActions[api.PIIEmail])
	}
	if c.DLPActions[api.PIIAPIKey] != api.DLPActionWarn {
		t.Errorf("api_key should be warn, got %v", c.DLPActions[api.PIIAPIKey])
	}
	if c.DLPDefault != api.DLPActionRedact {
		t.Errorf("default should be redact, got %v", c.DLPDefault)
	}
	if c.InjectionThreshold != 50 {
		t.Errorf("injection threshold should be 50, got %d", c.InjectionThreshold)
	}
	if len(c.Rules) != 5 {
		t.Errorf("want 5 rule summaries, got %d", len(c.Rules))
	}
}

func TestCompileUnknownKind(t *testing.T) {
	src := []byte(`
schema_version: v1.0
rules:
  - if: detects blockchain_key
    then: block
`)
	_, err := Compile(src)
	if err == nil {
		t.Fatal("expected error on unknown kind")
	}
	if !errors.Is(err, api.ErrConfigInvalid) {
		t.Errorf("want ErrConfigInvalid, got %v", err)
	}
	if !strings.Contains(err.Error(), "unknown detection kind") {
		t.Errorf("error should mention 'unknown detection kind': %v", err)
	}
}

func TestCompileBadAction(t *testing.T) {
	src := []byte(`
schema_version: v1.0
rules:
  - if: detects ssn
    then: silence
`)
	_, err := Compile(src)
	if err == nil {
		t.Fatal("expected error on bad action")
	}
}

func TestCompileBadCondition(t *testing.T) {
	src := []byte(`
schema_version: v1.0
rules:
  - if: whenever ssn
    then: block
`)
	_, err := Compile(src)
	if err == nil {
		t.Fatal("expected error on unknown condition")
	}
	if !strings.Contains(err.Error(), "not recognized") {
		t.Errorf("error should mention 'not recognized': %v", err)
	}
}

func TestInjectionGreaterThan(t *testing.T) {
	src := []byte(`
schema_version: v1.0
rules:
  - if: injection_score > 40
    then: block
`)
	c, err := Compile(src)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if c.InjectionThreshold != 41 {
		t.Errorf("> 40 should become threshold 41, got %d", c.InjectionThreshold)
	}
}

func TestMergeOverride(t *testing.T) {
	base := map[api.PIIKind]api.DLPAction{
		api.PIISSN:   api.DLPActionRedact,
		api.PIIEmail: api.DLPActionRedact,
	}
	c := &Compiled{
		DLPActions: map[api.PIIKind]api.DLPAction{
			api.PIISSN: api.DLPActionBlock, // upgrade
		},
	}
	out, _, _ := Merge(base, api.DLPActionRedact, 50, c)
	if out[api.PIISSN] != api.DLPActionBlock {
		t.Errorf("DSL should override; got %v", out[api.PIISSN])
	}
	if out[api.PIIEmail] != api.DLPActionRedact {
		t.Errorf("base value should survive; got %v", out[api.PIIEmail])
	}
}
