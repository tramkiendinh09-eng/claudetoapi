package gw

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"claudetoapi/internal/store"
)

func TestAcceptableUAOfficialSuffix(t *testing.T) {
	ok := []string{
		"claude-cli/2.1.247",
		"claude-cli/2.1.247 (external, cli)",
		"claude-cli/2.1.246 (external, sdk-cli)",
		"claude-cli/2.1.247 (external, claude-vscode)",
		"claude-cli/2.1.247 (external, cli, agent-sdk/0.1.0)",
	}
	for _, ua := range ok {
		if !acceptableUA(ua) {
			t.Fatalf("should accept official UA %q", ua)
		}
	}
	bad := []string{
		"",
		"Go-http-client/2.0",
		"claude-cli/2.1.247-local",
		"claude-cli/2.1.247 (internal, cli)",
		"claude-cli/999.0.0 (external, cli)",
		"Mozilla/5.0",
	}
	for _, ua := range bad {
		if acceptableUA(ua) {
			t.Fatalf("should reject %q", ua)
		}
	}
}

func TestVersionTripleOfficialSuffix(t *testing.T) {
	v, ok := versionTriple("claude-cli/2.1.247 (external, cli)")
	if !ok || v != [3]int{2, 1, 247} {
		t.Fatalf("got %v ok=%v", v, ok)
	}
	if !newerVersion("claude-cli/2.1.247 (external, cli)", "claude-cli/2.1.241 (external, cli)") {
		t.Fatal("2.1.247 must be newer than 2.1.241")
	}
}

func TestFingerprintIgnoresInboundUAAndFreezesProfile(t *testing.T) {
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	acc := addAccount(t, st, "pool")
	old := &store.Fingerprint{
		ClientID:   strings.Repeat("ab", 32),
		Entrypoint: "cli",
		Profile:    "2.1.241",
		UserAgent:  "claude-cli/2.1.241 (external, cli)",
		SDKVersion: "0.208.0",
		UpdatedAt:  time.Now().Add(-time.Hour).Unix(),
	}
	if err := st.Update(acc.ID, func(a *store.Account) { a.Fingerprint = old }); err != nil {
		t.Fatal(err)
	}
	acc, _ = st.Get(acc.ID)

	fp, prof := g.resolveFingerprint(acc, "claude-cli/2.1.246 (external, cli)")
	if prof.CLIVersion != "2.1.241" {
		t.Fatalf("frozen profile = %s", prof.CLIVersion)
	}
	if fp.UserAgent != "claude-cli/2.1.241 (external, cli)" {
		t.Fatalf("sticky UA mutated, got %q", fp.UserAgent)
	}
	if strings.Contains(fp.UserAgent, "2.1.246") {
		t.Fatal("inbound 2.1.246 must not be adopted")
	}
	if fp.OS != "Linux" || fp.Arch != "arm64" {
		t.Fatalf("sticky platform = %s/%s", fp.OS, fp.Arch)
	}

	fp2, _ := g.resolveFingerprint(acc, "Go-http-client/2.0")
	if fp2.UserAgent != "claude-cli/2.1.241 (external, cli)" {
		t.Fatalf("sticky UA drifted to %q", fp2.UserAgent)
	}
}

func TestPoolIdentityStampsFingerprintForGenuineCLI(t *testing.T) {
	var gotUA, gotOS, gotArch, gotSDK string
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotOS = r.Header.Get("X-Stainless-OS")
		gotArch = r.Header.Get("X-Stainless-Arch")
		gotSDK = r.Header.Get("X-Stainless-Package-Version")
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	acc := addAccount(t, st, "pool")
	_ = st.Update(acc.ID, func(a *store.Account) {
		a.Fingerprint = &store.Fingerprint{
			ClientID:   strings.Repeat("cd", 32),
			Entrypoint: "cli",
			Profile:    "2.1.241",
			UserAgent:  "claude-cli/2.1.241 (external, cli)",
			SDKVersion: "0.208.0",
		}
	})

	body := `{"model":"claude-sonnet-4-5-20250929","max_tokens":64,"messages":[{"role":"user","content":"hi there from cli"}],"metadata":{"user_id":"{\"device_id\":\"x\",\"account_uuid\":\"\",\"session_id\":\"11111111-1111-4111-8111-111111111111\"}"},"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.246.abc; cc_entrypoint=cli;"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("User-Agent", "claude-cli/2.1.246 (external, cli)")
	req.Header.Set("X-Stainless-OS", "Windows")
	req.Header.Set("X-Stainless-Arch", "x64")
	req.Header.Set("X-Stainless-Package-Version", "0.99.0")
	w := httptest.NewRecorder()
	g.handleMessages(w, req, false)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if gotUA != "claude-cli/2.1.241 (external, cli)" {
		t.Fatalf("upstream UA = %q, want frozen sticky 2.1.241", gotUA)
	}
	if gotOS != "Linux" || gotArch != "arm64" {
		t.Fatalf("upstream stainless = %s/%s (inbound Windows/x64 must not leak)", gotOS, gotArch)
	}
	if gotSDK != "0.208.0" {
		t.Fatalf("sdk = %q", gotSDK)
	}
}
