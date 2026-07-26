package tlsinspect

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"cloakline/internal/obs/log"
)

// buildChatBody produces a realistic /v1/messages payload with `nMsgs`
// prior turns of `paraLen` chars each, plus a final user message that
// optionally carries secrets. This models the CPU cost the proxy adds
// on top of the unavoidable network round-trip.
func buildChatBody(nMsgs, paraLen int, withSecrets bool) []byte {
	para := strings.Repeat("the quick brown fox jumps over the lazy dog. ", paraLen/45+1)
	msgs := make([]map[string]any, 0, nMsgs+1)
	for i := 0; i < nMsgs; i++ {
		role := "user"
		if i%2 == 1 {
			role = "assistant"
		}
		msgs = append(msgs, map[string]any{"role": role, "content": para})
	}
	last := "please review this config and help me debug it. " + para
	if withSecrets {
		last += " my password is hunter2Xy and the api key is 8f3a9c2d4e5b6071 " +
			"and my card is 4111 1111 1111 1111 and ssn: 123-45-6789 " +
			"token = ghp_aBc12345Xyz9988 email me at dev@example.com"
	}
	msgs = append(msgs, map[string]any{"role": "user", "content": last})
	body, _ := json.Marshal(map[string]any{
		"model":      "claude-sonnet-4-6",
		"max_tokens": 1024,
		"messages":   msgs,
	})
	return body
}

func benchDLP(b *testing.B, nMsgs, paraLen int, withSecrets bool) {
	h := NewHandler(HandlerConfig{
		Logger:     log.New(log.LevelError),
		DLPActions: fakeActionResolver{},
	})
	body := buildChatBody(nMsgs, paraLen, withSecrets)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		vault := newLocalVault()
		_ = h.applyDLPToJSON(body, false, vault)
	}
}

// Small: a short single-turn prompt, no secrets — the common case.
func BenchmarkDLP_Small_Clean(b *testing.B)   { benchDLP(b, 1, 200, false) }
func BenchmarkDLP_Small_Secrets(b *testing.B) { benchDLP(b, 1, 200, true) }

// Medium: a 10-turn conversation with a few KB per turn.
func BenchmarkDLP_Medium_Clean(b *testing.B)   { benchDLP(b, 10, 2000, false) }
func BenchmarkDLP_Medium_Secrets(b *testing.B) { benchDLP(b, 10, 2000, true) }

// Large: a long 40-turn conversation, ~8KB per turn (~320KB body).
func BenchmarkDLP_Large_Clean(b *testing.B)   { benchDLP(b, 40, 8000, false) }
func BenchmarkDLP_Large_Secrets(b *testing.B) { benchDLP(b, 40, 8000, true) }

// sanity keeps the fmt import used if the file is trimmed during edits.
var _ = fmt.Sprintf
