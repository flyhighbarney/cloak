// Package config loads and validates the four config files
// (providers.yaml, principals.yaml, policies.cel-yaml, pipeline.yaml) into a
// content-addressed IR. See docs/versioning.md for the schema version rules.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"policyd/internal/api"
	"policyd/internal/auth"
	"policyd/internal/policy/dsl"
)

const (
	CurrentSchemaVersion = "v1.0"
	MaxFileSize          = 128 * 1024
)

// Env is the deployment environment marker.
type Env string

const (
	EnvDev  Env = "dev"
	EnvProd Env = "prod"
)

// SecurityMode gates governance invariants at boot. See docs/threat-model.md G1.
type SecurityMode string

const (
	SecurityDev        SecurityMode = "dev"
	SecurityPermissive SecurityMode = "permissive"
	SecurityStrict     SecurityMode = "strict"
)

// IR is the compiled, validated configuration.
type IR struct {
	Hash          string
	Loaded        time.Time
	Env           Env
	SecurityMode  SecurityMode
	Listen        string
	AdminListen   string
	MaxBodyBytes  int64
	RequestTimeout time.Duration
	DLP           DLPIR
	Injection     InjectionIR
	Inspect       InspectIR
	Providers     []ProviderIR
	Principals    []PrincipalIR
	Policies      []PolicyIR
	Pipeline      PipelineIR
	Budgets       map[api.BudgetRef]BudgetIR
	RateLimit     RateLimitIR
}

// BudgetIR describes a per-budget-ref daily limit set.
type BudgetIR struct {
	DailyRequests int
}

// RateLimitIR describes the per-key rate limit.
type RateLimitIR struct {
	PerSecond float64
	Burst     float64
}

// DLPIR is the compiled DLP configuration.
type DLPIR struct {
	Default api.DLPAction
	ByKind  map[api.PIIKind]api.DLPAction
}

// InjectionIR is the compiled prompt-injection detection configuration.
type InjectionIR struct {
	Threshold int
}

// InspectIR is the compiled TLS-inspection module configuration.
// When Enabled is false, the module is not started at all.
type InspectIR struct {
	Enabled bool
	Listen  string   // e.g. ":8443"
	Hosts   []string // hostnames to inspect (api.openai.com, api.anthropic.com, ...)
	CADir   string   // directory holding ca-cert.pem / ca-key.pem
}

type ProviderIR struct {
	ID         api.UpstreamID
	Kind       api.UpstreamKind
	BaseURL    string
	APIKeyEnv  string // env var name; the value is loaded from env, never from YAML
	Model      string
	MaxContext int
	CostIn     float64
	CostOut    float64
	Local      bool // if true, allowlist loopback for SSRF
}

type PrincipalIR struct {
	KeyPlaintext  string // stripped from Hash; not written back
	TenantID      api.TenantID
	KeyID         api.KeyID
	Scopes        []api.Scope
	BudgetRef     api.BudgetRef
	RoutingPolicy api.PolicyRef
	Expiry        time.Time
	Metadata      map[string]string
}

type PolicyIR struct {
	ID         api.PolicyRuleID
	APIVersion string
	Kind       api.PolicyKind
	Expression string
}

type PipelineIR struct {
	Stages []string // ordered stage IDs (informational; DAG resolves order)
}

// -------- YAML shapes --------

type pipelineFile struct {
	SchemaVersion     string                     `yaml:"schema_version"`
	Env               Env                        `yaml:"env"`
	Security          SecurityMode               `yaml:"security"`
	Listen            string                     `yaml:"listen"`
	AdminListen       string                     `yaml:"admin_listen"`
	MaxBodyBytes      int64                      `yaml:"max_body_bytes"`
	RequestTimeoutSec int                        `yaml:"request_timeout_seconds"`
	Stages            []string                   `yaml:"stages"`
	DLP               *dlpSection                `yaml:"dlp"`
	Injection         *injectionSection          `yaml:"injection"`
	Budgets           map[string]budgetEntry     `yaml:"budgets"`
	RateLimit         *rateLimitSection          `yaml:"rate_limit"`
	Inspect           *inspectSection            `yaml:"inspect"`
}

type inspectSection struct {
	Enabled bool     `yaml:"enabled"`
	Listen  string   `yaml:"listen"`
	Hosts   []string `yaml:"hosts"`
	CADir   string   `yaml:"ca_dir"`
}

type dlpSection struct {
	Default string            `yaml:"default"` // allow | warn | redact | block
	Actions map[string]string `yaml:"actions"` // finding_kind -> action
}

type injectionSection struct {
	Threshold int `yaml:"threshold"`
}

type budgetEntry struct {
	DailyRequests int `yaml:"daily_requests"`
}

type rateLimitSection struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             float64 `yaml:"burst"`
}

type providersFile struct {
	SchemaVersion string           `yaml:"schema_version"`
	Providers     []providerEntry  `yaml:"providers"`
}

type providerEntry struct {
	ID         string  `yaml:"id"`
	Kind       string  `yaml:"kind"`
	BaseURL    string  `yaml:"base_url"`
	APIKeyEnv  string  `yaml:"api_key_env"`
	APIKey     string  `yaml:"api_key,omitempty"` // rejected if non-empty; secrets must come from env
	Model      string  `yaml:"model"`
	MaxContext int     `yaml:"max_context"`
	CostIn     float64 `yaml:"cost_per_1k_in"`
	CostOut    float64 `yaml:"cost_per_1k_out"`
	Local      bool    `yaml:"local"`
}

type principalsFile struct {
	SchemaVersion string            `yaml:"schema_version"`
	Principals    []principalEntry  `yaml:"principals"`
}

type principalEntry struct {
	Key           string            `yaml:"key"`
	TenantID      string            `yaml:"tenant_id"`
	KeyID         string            `yaml:"key_id"`
	Scopes        []string          `yaml:"scopes"`
	BudgetRef     string            `yaml:"budget_ref"`
	RoutingPolicy string            `yaml:"routing_policy"`
	ExpirySec     int64             `yaml:"expiry_unix"`
	Metadata      map[string]string `yaml:"metadata"`
}

type policiesFile struct {
	SchemaVersion string        `yaml:"schema_version"`
	Policies      []policyEntry `yaml:"policies"`
}

type policyEntry struct {
	ID         string `yaml:"id"`
	APIVersion string `yaml:"api_version"`
	Kind       string `yaml:"kind"`
	Expression string `yaml:"expression"`
}

// Load reads the four files from a config directory and compiles the IR.
func Load(dir string) (*IR, error) {
	pipelinePath := filepath.Join(dir, "pipeline.yaml")
	providersPath := filepath.Join(dir, "providers.yaml")
	principalsPath := filepath.Join(dir, "principals.yaml")
	policiesPath := filepath.Join(dir, "policies.yaml")

	pipelineBytes, err := readCapped(pipelinePath)
	if err != nil {
		return nil, err
	}
	providersBytes, err := readCapped(providersPath)
	if err != nil {
		return nil, err
	}
	principalsBytes, err := readCapped(principalsPath)
	if err != nil {
		return nil, err
	}
	policiesBytes, err := readCapped(policiesPath)
	if err != nil {
		return nil, err
	}

	var pf pipelineFile
	if err := strictYAML(pipelineBytes, &pf); err != nil {
		return nil, fmt.Errorf("pipeline.yaml: %w", err)
	}
	if err := validateSchema(pf.SchemaVersion); err != nil {
		return nil, fmt.Errorf("pipeline.yaml: %w", err)
	}
	var prf providersFile
	if err := strictYAML(providersBytes, &prf); err != nil {
		return nil, fmt.Errorf("providers.yaml: %w", err)
	}
	if err := validateSchema(prf.SchemaVersion); err != nil {
		return nil, fmt.Errorf("providers.yaml: %w", err)
	}
	var pnf principalsFile
	if err := strictYAML(principalsBytes, &pnf); err != nil {
		return nil, fmt.Errorf("principals.yaml: %w", err)
	}
	if err := validateSchema(pnf.SchemaVersion); err != nil {
		return nil, fmt.Errorf("principals.yaml: %w", err)
	}
	var pf2 policiesFile
	if err := strictYAML(policiesBytes, &pf2); err != nil {
		return nil, fmt.Errorf("policies.yaml: %w", err)
	}
	if err := validateSchema(pf2.SchemaVersion); err != nil {
		return nil, fmt.Errorf("policies.yaml: %w", err)
	}

	ir := &IR{
		Loaded:         time.Now().UTC(),
		Env:            pf.Env,
		SecurityMode:   pf.Security,
		Listen:         defaultString(pf.Listen, ":4000"),
		AdminListen:    defaultString(pf.AdminListen, ":4001"),
		MaxBodyBytes:   defaultInt64(pf.MaxBodyBytes, 4<<20),
		RequestTimeout: time.Duration(defaultInt(pf.RequestTimeoutSec, 30)) * time.Second,
		Pipeline:       PipelineIR{Stages: pf.Stages},
	}

	if err := validateEnv(ir.Env); err != nil {
		return nil, err
	}
	if err := validateSecurity(ir.SecurityMode); err != nil {
		return nil, err
	}

	// DLP action map.
	if pf.DLP != nil {
		ir.DLP.Default = api.ParseDLPAction(pf.DLP.Default)
		if ir.DLP.Default == api.DLPActionUnknown && pf.DLP.Default != "" {
			return nil, fmt.Errorf("%w: unknown dlp.default %q", api.ErrConfigInvalid, pf.DLP.Default)
		}
		ir.DLP.ByKind = make(map[api.PIIKind]api.DLPAction, len(pf.DLP.Actions))
		for k, v := range pf.DLP.Actions {
			act := api.ParseDLPAction(v)
			if act == api.DLPActionUnknown {
				return nil, fmt.Errorf("%w: unknown dlp.actions.%s = %q", api.ErrConfigInvalid, k, v)
			}
			ir.DLP.ByKind[api.PIIKind(k)] = act
		}
	}
	if ir.DLP.Default == api.DLPActionUnknown {
		ir.DLP.Default = api.DLPActionRedact
	}

	// Injection config.
	if pf.Injection != nil {
		ir.Injection.Threshold = pf.Injection.Threshold
	}
	if ir.Injection.Threshold <= 0 {
		ir.Injection.Threshold = 50
	}

	// Budgets.
	ir.Budgets = make(map[api.BudgetRef]BudgetIR, len(pf.Budgets))
	for name, b := range pf.Budgets {
		ir.Budgets[api.BudgetRef(name)] = BudgetIR{DailyRequests: b.DailyRequests}
	}

	// Rate limit.
	if pf.RateLimit != nil {
		ir.RateLimit.PerSecond = pf.RateLimit.RequestsPerSecond
		ir.RateLimit.Burst = pf.RateLimit.Burst
	}

	// TLS inspection module.
	if pf.Inspect != nil {
		ir.Inspect.Enabled = pf.Inspect.Enabled
		ir.Inspect.Listen = defaultString(pf.Inspect.Listen, ":8443")
		ir.Inspect.Hosts = pf.Inspect.Hosts
		ir.Inspect.CADir = pf.Inspect.CADir
	}

	// Optional rules.yaml DSL overlay. When present, its DLP action + injection
	// threshold overrides win over pipeline.yaml values.
	rulesPath := filepath.Join(dir, "rules.yaml")
	if buf, rerr := readCappedIfExists(rulesPath); rerr != nil {
		return nil, rerr
	} else if buf != nil {
		compiled, cerr := dsl.Compile(buf)
		if cerr != nil {
			return nil, fmt.Errorf("rules.yaml: %w", cerr)
		}
		ir.DLP.ByKind, ir.DLP.Default, ir.Injection.Threshold = dsl.Merge(
			ir.DLP.ByKind, ir.DLP.Default, ir.Injection.Threshold, compiled)
	}

	// Providers.
	seenProv := make(map[string]bool)
	for _, p := range prf.Providers {
		if p.APIKey != "" {
			return nil, fmt.Errorf("%w: providers.yaml carries inline api_key for %q; use api_key_env",
				api.ErrConfigInvalid, p.ID)
		}
		if p.APIKeyEnv == "" {
			return nil, fmt.Errorf("%w: providers.yaml missing api_key_env for %q",
				api.ErrConfigInvalid, p.ID)
		}
		if seenProv[p.ID] {
			return nil, fmt.Errorf("%w: duplicate provider id %q", api.ErrConfigInvalid, p.ID)
		}
		seenProv[p.ID] = true
		kind := api.UpstreamKind(p.Kind)
		if !knownKind(kind) {
			return nil, fmt.Errorf("%w: unknown provider kind %q", api.ErrConfigInvalid, p.Kind)
		}
		ir.Providers = append(ir.Providers, ProviderIR{
			ID:         api.UpstreamID(p.ID),
			Kind:       kind,
			BaseURL:    p.BaseURL,
			APIKeyEnv:  p.APIKeyEnv,
			Model:      p.Model,
			MaxContext: p.MaxContext,
			CostIn:     p.CostIn,
			CostOut:    p.CostOut,
			Local:      p.Local,
		})
	}

	// Principals.
	seenKey := make(map[string]bool)
	for _, p := range pnf.Principals {
		if !strings.HasPrefix(p.Key, "sk-gw-") {
			return nil, fmt.Errorf("%w: principal key must be sk-gw-* (id=%s)",
				api.ErrConfigInvalid, p.KeyID)
		}
		if seenKey[p.Key] {
			return nil, fmt.Errorf("%w: duplicate principal key", api.ErrConfigInvalid)
		}
		seenKey[p.Key] = true
		scopes := make([]api.Scope, len(p.Scopes))
		for i, s := range p.Scopes {
			scopes[i] = api.Scope(s)
		}
		var expiry time.Time
		if p.ExpirySec > 0 {
			expiry = time.Unix(p.ExpirySec, 0).UTC()
		}
		ir.Principals = append(ir.Principals, PrincipalIR{
			KeyPlaintext:  p.Key,
			TenantID:      api.TenantID(p.TenantID),
			KeyID:         api.KeyID(p.KeyID),
			Scopes:        scopes,
			BudgetRef:     api.BudgetRef(p.BudgetRef),
			RoutingPolicy: api.PolicyRef(p.RoutingPolicy),
			Expiry:        expiry,
			Metadata:      p.Metadata,
		})
	}

	// Policies.
	seenPol := make(map[string]bool)
	for _, p := range pf2.Policies {
		if seenPol[p.ID] {
			return nil, fmt.Errorf("%w: duplicate policy id %q", api.ErrConfigInvalid, p.ID)
		}
		seenPol[p.ID] = true
		kind := api.PolicyKind(p.Kind)
		if kind != api.PolicyKindRouting {
			return nil, fmt.Errorf("%w: only routing policies supported in Phase 1 (id=%s)",
				api.ErrConfigInvalid, p.ID)
		}
		ir.Policies = append(ir.Policies, PolicyIR{
			ID:         api.PolicyRuleID(p.ID),
			APIVersion: p.APIVersion,
			Kind:       kind,
			Expression: p.Expression,
		})
	}

	// Cross-references: each principal's routing_policy must exist.
	for _, pr := range ir.Principals {
		if pr.RoutingPolicy == "" {
			continue
		}
		if !hasPolicy(ir.Policies, pr.RoutingPolicy) {
			return nil, fmt.Errorf("%w: principal %s references unknown routing_policy %q",
				api.ErrConfigInvalid, pr.KeyID, pr.RoutingPolicy)
		}
	}

	// Governance invariants (see docs/threat-model.md G1, G2).
	if ir.Env == EnvProd {
		if ir.SecurityMode != SecurityStrict {
			return nil, fmt.Errorf("%w: env=prod requires security=strict", api.ErrConfigInvalid)
		}
	}

	// Hash all four source bytes for drift detection.
	h := sha256.New()
	h.Write([]byte("pipeline:"))
	h.Write(pipelineBytes)
	h.Write([]byte("providers:"))
	h.Write(providersBytes)
	h.Write([]byte("principals:"))
	// Include principals in the hash BUT scrub keys out first so a key
	// rotation doesn't create a false "drift" alert. We hash the key-hashes.
	h.Write([]byte(fmt.Sprintf("%d", len(pnf.Principals))))
	for _, p := range pnf.Principals {
		h.Write([]byte(p.KeyID))
	}
	h.Write([]byte("policies:"))
	h.Write(policiesBytes)
	ir.Hash = hex.EncodeToString(h.Sum(nil))

	return ir, nil
}

// LoadIntoAuth converts principals to an auth.Store.
func LoadIntoAuth(ir *IR) (*auth.Store, error) {
	store := auth.NewStore()
	for _, p := range ir.Principals {
		if err := store.Add(p.KeyPlaintext, api.Principal{
			APIVersion:    "v1.0",
			TenantID:      p.TenantID,
			KeyID:         p.KeyID,
			Scopes:        p.Scopes,
			BudgetRef:     p.BudgetRef,
			RoutingPolicy: p.RoutingPolicy,
			Expiry:        p.Expiry,
			AuditID:       api.AuditID(p.KeyID),
			Metadata:      p.Metadata,
		}); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// APIKeyForProvider fetches the plaintext key from the environment.
// The env-var name comes from the IR; the value never sits in a file.
func APIKeyForProvider(p ProviderIR) (string, error) {
	v := os.Getenv(p.APIKeyEnv)
	if v == "" {
		return "", fmt.Errorf("%w: env %s not set for provider %s",
			api.ErrConfigInvalid, p.APIKeyEnv, p.ID)
	}
	if strings.HasPrefix(v, "sk-") && !strings.HasPrefix(v, "sk-gw-") {
		// It's a real cloud key. Good — that's what we expect.
	}
	return v, nil
}

// -------- helpers --------

func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	buf, err := io.ReadAll(io.LimitReader(f, MaxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(buf) > MaxFileSize {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", api.ErrConfigInvalid, path, MaxFileSize)
	}
	return buf, nil
}

// readCappedIfExists is like readCapped but returns (nil, nil) if the file
// does not exist. Used for optional overlay files (rules.yaml).
func readCappedIfExists(path string) ([]byte, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return readCapped(path)
}

func strictYAML(b []byte, dst any) error {
	dec := yaml.NewDecoder(bytesReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: empty config", api.ErrConfigInvalid)
		}
		return fmt.Errorf("%w: %v", api.ErrConfigInvalid, err)
	}
	return nil
}

func bytesReader(b []byte) *strings.Reader { return strings.NewReader(string(b)) }

func validateSchema(v string) error {
	if v != CurrentSchemaVersion {
		return fmt.Errorf("%w: schema_version %q; want %q",
			api.ErrConfigInvalid, v, CurrentSchemaVersion)
	}
	return nil
}

func validateEnv(e Env) error {
	if e != EnvDev && e != EnvProd {
		return fmt.Errorf("%w: env must be dev|prod", api.ErrConfigInvalid)
	}
	return nil
}

func validateSecurity(m SecurityMode) error {
	if m != SecurityDev && m != SecurityPermissive && m != SecurityStrict {
		return fmt.Errorf("%w: security must be dev|permissive|strict", api.ErrConfigInvalid)
	}
	return nil
}

func knownKind(k api.UpstreamKind) bool {
	switch k {
	case api.KindOpenAI, api.KindAnthropic, api.KindOllama, api.KindVLLM,
		api.KindBedrock, api.KindGemini, api.KindMock:
		return true
	}
	return false
}

func hasPolicy(ps []PolicyIR, ref api.PolicyRef) bool {
	for _, p := range ps {
		if api.PolicyRef(p.ID) == ref {
			return true
		}
	}
	return false
}

func defaultString(v, dflt string) string {
	if v == "" {
		return dflt
	}
	return v
}

func defaultInt64(v, dflt int64) int64 {
	if v == 0 {
		return dflt
	}
	return v
}

func defaultInt(v, dflt int) int {
	if v == 0 {
		return dflt
	}
	return v
}
