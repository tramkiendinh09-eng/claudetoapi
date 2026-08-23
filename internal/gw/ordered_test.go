package gw

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"claudetoapi/internal/mimicry"
)

// TestWriteOrderedRequestHeaderOrder pins the wire order: Host first, then
// the real CLI's header sequence, content-length last. Go's stock writer
// would alphabetize — this is the regression guard.
func TestWriteOrderedRequestHeaderOrder(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages?beta=true", bytes.NewReader([]byte(`{}`)))
	req.Header = BuildUpstreamHeaders(HeaderBuildInput{
		Token:         "tok",
		Beta:          "claude-code-20250219,oauth-2025-04-20",
		Profile:       testProfile(),
		UserAgent:     "claude-cli/2.1.241 (external, cli)",
		SDKVersion:    "0.208.0",
		SessionID:     "474107af-f17f-4ffc-a02a-1f017c7ae71f",
		ClientReqID:   "d0f0f4b4-1111-2222-3333-444455556666",
		AcceptLanguage: "en-US,en;q=0.9",
		Mimic:         true,
	})

	var buf bytes.Buffer
	if err := writeOrderedRequest(&buf, req, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// Order assertions (positions must strictly increase).
	pos := func(name string) int { return strings.Index(out, name+":") }
	ordered := []string{
		"Host", "Accept", "X-Stainless-Retry-Count", "X-Stainless-Timeout",
		"X-Stainless-Lang", "X-Stainless-Package-Version", "X-Stainless-OS",
		"X-Stainless-Arch", "X-Stainless-Runtime", "X-Stainless-Runtime-Version",
		"anthropic-version", "authorization", "x-app", "User-Agent",
		"X-Claude-Code-Session-Id", "content-type", "anthropic-beta",
		"x-client-request-id", "accept-language", "content-length",
	}
	last := -1
	for _, h := range ordered {
		p := pos(h)
		if p < 0 {
			t.Fatalf("header %s missing from wire output:\n%s", h, out)
		}
		if p <= last {
			t.Fatalf("header %s out of wire order (pos %d after %d):\n%s", h, p, last, out)
		}
		last = p
	}
	if !strings.Contains(out, "Host: api.anthropic.com\r\n") {
		t.Fatalf("Host header must be first and explicit:\n%s", out)
	}
	if !strings.HasSuffix(out, "content-length: 2\r\n\r\n{}") {
		t.Fatalf("request must end with body:\n%q", out)
	}
}

// TestShiftDatelines verifies dateline alignment with the exit timezone.
func TestShiftDatelines(t *testing.T) {
	body := map[string]any{
		"system": "Today's date is 2026-08-22.",
		"messages": []any{
			map[string]any{"role": "user", "content": "<system-reminder>\nToday's date is 2026-08-22.\n</system-reminder> hello"},
		},
	}
	if !mimicry.ShiftDatelines(body, "2026-08-23") {
		t.Fatal("expected dateline shift")
	}
	if body["system"] != "Today's date is 2026-08-23." {
		t.Fatalf("system dateline not shifted: %v", body["system"])
	}
	msg := body["messages"].([]any)[0].(map[string]any)
	if !strings.Contains(msg["content"].(string), "Today's date is 2026-08-23.") {
		t.Fatalf("reminder dateline not shifted: %v", msg["content"])
	}
	// Idempotent: same date no-op.
	if mimicry.ShiftDatelines(body, "2026-08-23") {
		t.Fatal("same-date shift must be a no-op")
	}
}
