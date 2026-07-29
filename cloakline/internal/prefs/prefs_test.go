package prefs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// openAt makes a Store rooted in a caller-supplied dir. Test-only —
// lets us avoid touching the user's real config dir.
func openAt(t *testing.T, dir string) *Store {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	s := &Store{
		dir:      dir,
		keyFile:  filepath.Join(dir, "prefs.key"),
		dataFile: filepath.Join(dir, "prefs.bin"),
	}
	key, err := s.loadOrCreateKey()
	if err != nil {
		t.Fatalf("loadOrCreateKey: %v", err)
	}
	s.cachedKey = key
	t.Cleanup(s.Close)
	return s
}

func TestSaveLoadRoundTrip(t *testing.T) {
	s := openAt(t, t.TempDir())
	in := Prefs{
		Kinds: map[string]KindPref{
			"email":       {Action: "allow"},
			"phone":       {Action: "redact"},
			"ip_address":  {Action: "flag"},
		},
		SessionOptoutTTLSeconds: 3600,
	}
	if err := s.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out.SessionOptoutTTLSeconds != 3600 {
		t.Errorf("TTL round-trip: got %d", out.SessionOptoutTTLSeconds)
	}
	if len(out.Kinds) != 3 || out.Kinds["email"].Action != "allow" {
		t.Errorf("Kinds round-trip: got %+v", out.Kinds)
	}
}

func TestLoadMissingReturnsEmpty(t *testing.T) {
	s := openAt(t, t.TempDir())
	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load on empty: %v", err)
	}
	if len(got.Kinds) != 0 {
		t.Errorf("empty prefs should have zero kinds, got %v", got.Kinds)
	}
}

func TestSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	// First run: save.
	{
		s := openAt(t, dir)
		if err := s.Save(Prefs{Kinds: map[string]KindPref{"email": {Action: "allow"}}}); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	// Second run: fresh store, same dir.
	s2 := openAt(t, dir)
	got, err := s2.Load()
	if err != nil {
		t.Fatalf("Load after restart: %v", err)
	}
	if got.Kinds["email"].Action != "allow" {
		t.Fatalf("prefs did not survive restart: %+v", got)
	}
}

// TestNoPlaintextOnDisk is the paranoia test: the JSON body must not
// appear anywhere in the encrypted file.
func TestNoPlaintextOnDisk(t *testing.T) {
	s := openAt(t, t.TempDir())
	needle := "very-distinctive-marker-string-32aab"
	err := s.Save(Prefs{Kinds: map[string]KindPref{
		"email": {Action: needle},
	}})
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(s.dataFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(raw, []byte(needle)) {
		t.Fatal("prefs.bin contains plaintext — encryption is broken")
	}
}

// TestConcurrentLoadSaveIsRaceFree is the regression test for the
// prefs mutex fix. Under -race, this should never trip.
func TestConcurrentLoadSaveIsRaceFree(t *testing.T) {
	s := openAt(t, t.TempDir())
	// Seed a value so Load returns non-empty.
	_ = s.Save(Prefs{Kinds: map[string]KindPref{"email": {Action: "redact"}}})

	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			_ = s.Save(Prefs{Kinds: map[string]KindPref{
				"email": {Action: "redact"},
				"phone": {Action: "redact"},
			}})
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		if _, ok := s.ActionForKind("email"); !ok {
			t.Fatalf("email override disappeared under concurrent Save (iter %d)", i)
		}
	}
	<-done
}

func TestActionForKind(t *testing.T) {
	s := openAt(t, t.TempDir())
	_ = s.Save(Prefs{Kinds: map[string]KindPref{"email": {Action: "allow"}}})
	if a, ok := s.ActionForKind("email"); !ok || a != "allow" {
		t.Errorf("email override: got (%q,%v), want (allow,true)", a, ok)
	}
	if _, ok := s.ActionForKind("ssn"); ok {
		t.Errorf("ssn has no override; want (,false)")
	}
}
