package keyvault

import (
	"errors"
	"reflect"
	"testing"
)

func withFresh(t *testing.T) {
	t.Helper()
	prev := backend
	SetBackend(newMemoryBackend())
	t.Cleanup(func() { SetBackend(prev) })
}

func TestSetGetRoundTrip(t *testing.T) {
	withFresh(t)
	if err := Set("Anthropic", "sk-ant-abcd1234"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := Get("anthropic") // case-insensitive lookup
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "sk-ant-abcd1234" {
		t.Fatalf("Get returned %q, want the original", got)
	}
}

func TestGetMissingReturnsErrNotFound(t *testing.T) {
	withFresh(t)
	_, err := Get("openai")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestSetRejectsEmptyKey(t *testing.T) {
	withFresh(t)
	if err := Set("openai", "   "); err == nil {
		t.Fatal("empty key should be rejected")
	}
}

func TestSetRejectsBadProviderID(t *testing.T) {
	withFresh(t)
	bad := []string{"", "  ", "has space", "open ai", "OpenAI!", "provider/x"}
	for _, id := range bad {
		if err := Set(id, "x"); err == nil {
			t.Errorf("provider ID %q should be rejected", id)
		}
	}
}

func TestDelete(t *testing.T) {
	withFresh(t)
	_ = Set("openai", "sk-1")
	if err := Delete("openai"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Get("openai"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after Delete want ErrNotFound, got %v", err)
	}
	if err := Delete("openai"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double Delete want ErrNotFound, got %v", err)
	}
}

func TestListSorted(t *testing.T) {
	withFresh(t)
	_ = Set("openai", "x")
	_ = Set("anthropic", "x")
	_ = Set("cohere", "x")
	got, err := List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"anthropic", "cohere", "openai"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("List = %v, want %v", got, want)
	}
}

func TestMask(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"abc":                 "•••",
		"abcd":                "••••",
		"sk-ant-abcd1234":     "••••••••1234",
		"sk-proj-xyzXYZ00wxyz": "••••••••wxyz",
	}
	for in, want := range cases {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestActiveBackendName(t *testing.T) {
	withFresh(t)
	if got := ActiveBackendName(); got != "memory" {
		t.Fatalf("ActiveBackendName = %q, want memory", got)
	}
}

func TestSetBackendNilResetsToMemory(t *testing.T) {
	withFresh(t)
	SetBackend(nil)
	if got := ActiveBackendName(); got != "memory" {
		t.Fatalf("after SetBackend(nil), ActiveBackendName = %q, want memory", got)
	}
}
