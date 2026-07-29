package tlsinspect

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFailsafeRecoversPanicAndFailsOpen proves the automatic runtime failsafe:
// when the inspection pipeline panics BEFORE writing a response, the panic
// must not escape (daemon survives) and the untouched request must be replayed
// via failOpen so the caller still gets a working response.
func TestFailsafeRecoversPanicAndFailsOpen(t *testing.T) {
	panicHandle := func(w http.ResponseWriter, r *http.Request, host string) {
		panic("simulated pipeline crash")
	}
	var failOpenBody string
	failOpen := func(w http.ResponseWriter, r *http.Request, host string, body []byte) {
		failOpenBody = string(body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("failed-open-ok"))
	}

	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader(`{"hi":1}`))
	rec := httptest.NewRecorder()

	// Must not panic out of this call.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic escaped serveWithFailsafe: %v", r)
			}
		}()
		serveWithFailsafe(rec, req, "api.anthropic.com", 1<<20, nil, panicHandle, failOpen)
	}()

	if rec.Code != http.StatusOK {
		t.Fatalf("failsafe did not fail open: status %d", rec.Code)
	}
	if rec.Body.String() != "failed-open-ok" {
		t.Fatalf("unexpected body: %q", rec.Body.String())
	}
	if failOpenBody != `{"hi":1}` {
		t.Fatalf("failOpen got wrong body: %q", failOpenBody)
	}
}

// TestFailsafeNoRetryAfterPartialWrite: if the pipeline already began writing
// before panicking, we must NOT call failOpen (can't retry a half-sent
// response) — but the panic still must not escape.
func TestFailsafeNoRetryAfterPartialWrite(t *testing.T) {
	partialThenPanic := func(w http.ResponseWriter, r *http.Request, host string) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("partial"))
		panic("crash after write")
	}
	failOpenCalled := false
	failOpen := func(w http.ResponseWriter, r *http.Request, host string, body []byte) {
		failOpenCalled = true
	}

	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader("x"))
	rec := httptest.NewRecorder()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("panic escaped: %v", r)
			}
		}()
		serveWithFailsafe(rec, req, "api.anthropic.com", 1<<20, nil, partialThenPanic, failOpen)
	}()

	if failOpenCalled {
		t.Fatal("failOpen must not run after a partial write")
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status changed unexpectedly: %d", rec.Code)
	}
}

// TestFailsafeHappyPathUnaffected: with no panic, serveWithFailsafe behaves as
// a transparent pass-through to handle and never invokes failOpen.
func TestFailsafeHappyPathUnaffected(t *testing.T) {
	handle := func(w http.ResponseWriter, r *http.Request, host string) {
		b, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("handled:" + string(b)))
	}
	failOpen := func(w http.ResponseWriter, r *http.Request, host string, body []byte) {
		t.Fatal("failOpen must not run on the happy path")
	}

	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", strings.NewReader("payload"))
	rec := httptest.NewRecorder()
	serveWithFailsafe(rec, req, "api.anthropic.com", 1<<20, nil, handle, failOpen)

	if rec.Body.String() != "handled:payload" {
		t.Fatalf("body mismatch: %q", rec.Body.String())
	}
}
