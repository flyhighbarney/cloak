package audit

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct {
		name      string
		in        []string
		hadSecret bool
		hadPII    bool
	}{
		{"empty", nil, false, false},
		{"only email", []string{"email"}, false, true},
		{"only api_key", []string{"api_key"}, true, false},
		{"both", []string{"email", "api_key"}, true, true},
		{"unknown kind", []string{"weather"}, false, false},
		{"ssn and phone", []string{"ssn", "phone"}, false, true},
		{"aws + github", []string{"aws_key", "github_token"}, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, p := Classify(c.in)
			if s != c.hadSecret || p != c.hadPII {
				t.Fatalf("Classify(%v) = (%v,%v), want (%v,%v)", c.in, s, p, c.hadSecret, c.hadPII)
			}
		})
	}
}
