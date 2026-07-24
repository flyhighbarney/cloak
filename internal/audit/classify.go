package audit

// Category is a Brave-style bucket that groups the DLP-kind taxonomy
// into the three categories the dashboard tiles surface.
type Category int

const (
	CatSecret    Category = iota // api keys, tokens, private keys — the "must never leak" set
	CatPII                       // personal data — email, phone, SSN, name, credit card
	CatOtherFind                 // any finding that isn't secret or PII (reserved)
)

// secretKinds mirrors the PIIKind constants in internal/api/vault.go
// that represent credentials, not personal information.
var secretKinds = map[string]struct{}{
	"api_key":      {},
	"aws_key":      {},
	"github_token": {},
	"private_key":  {},
}

// piiKinds mirrors the PIIKind constants that represent personal data.
var piiKinds = map[string]struct{}{
	"email":       {},
	"phone":       {},
	"ssn":         {},
	"credit_card": {},
	"person_name": {},
}

// Classify buckets a slice of DLP finding kinds into (hadSecret,
// hadPII) booleans. An entry may set both if a request contained an
// email and an API key.
func Classify(kinds []string) (hadSecret, hadPII bool) {
	for _, k := range kinds {
		if _, ok := secretKinds[k]; ok {
			hadSecret = true
		}
		if _, ok := piiKinds[k]; ok {
			hadPII = true
		}
	}
	return
}
