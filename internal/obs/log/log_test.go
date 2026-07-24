package log

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactionAuthorizationHeader(t *testing.T) {
	var buf bytes.Buffer
	lg := NewWithWriter(&buf, LevelInfo)
	lg.Info("test", Fields{"Authorization": "Bearer sk-abc123secretkey"})
	line := buf.String()
	if strings.Contains(line, "sk-abc123secretkey") {
		t.Fatalf("plaintext secret leaked into log: %s", line)
	}
	if !strings.Contains(line, "redacted") {
		t.Fatalf("redaction marker missing: %s", line)
	}
}

func TestRedactionApiKey(t *testing.T) {
	var buf bytes.Buffer
	lg := NewWithWriter(&buf, LevelInfo)
	lg.Info("test", Fields{"api_key": "sk-plain-real-key"})
	if strings.Contains(buf.String(), "sk-plain-real-key") {
		t.Fatal("api_key not redacted")
	}
}

func TestSanitizeControlChars(t *testing.T) {
	var buf bytes.Buffer
	lg := NewWithWriter(&buf, LevelInfo)
	lg.Info("hi\n{\"level\":\"error\",\"msg\":\"fake\"}", nil)
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("log line not valid JSON: %v", err)
	}
	if strings.Contains(rec["msg"].(string), "\n") {
		t.Fatal("newline not sanitized in msg")
	}
}

func TestLevelFilter(t *testing.T) {
	var buf bytes.Buffer
	lg := NewWithWriter(&buf, LevelWarn)
	lg.Info("filtered", nil)
	lg.Warn("kept", nil)
	if strings.Contains(buf.String(), "filtered") {
		t.Fatal("below-min-level message not filtered")
	}
	if !strings.Contains(buf.String(), "kept") {
		t.Fatal("at-min-level message dropped")
	}
}
