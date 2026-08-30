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
	if !newerVersion("claude-cli/2.1.251 (external, cli)", "claude-cli/2.1.247 (external, cli)") {
		t.Fatal("2.1.251 must be newer than 2.1.247")
	}
}

func TestFingerprintIgnoresInboundUAAndUpgradesCLIVersion(t *testing.T) {
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
		OS:         "Linux",
		Arch:       "arm64",
		Runtime:    "node",
		RuntimeVersion: "v24.3.0",
		UpdatedAt:  time.Now().Add(-time.Hour).Unix(),
	}
	if err := st.Update(acc.ID, func(a *store.Account) { a.Fingerprint = old }); err != nil {
		t.Fatal(err)
	}
	acc, _ = st.Get(acc.ID)

	fp, prof := g.resolveFingerprint(acc, "claude-cli/2.1.246 (external, cli)")
	if prof.CLIVersion != "2.1.251" {
		t.Fatalf("upgraded profile = %s", prof.CLIVersion)
	}
	if fp.UserAgent != "claude-cli/2.1.251 (external, cli)" {
		t.Fatalf("sticky UA not upgraded, got %q", fp.UserAgent)
	}
	if strings.Contains(fp.UserAgent, "2.1.246") {
		t.Fatal("inbound 2.1.246 must not be adopted")
	}
	if fp.OS != "Linux" || fp.Arch != "arm64" {
		t.Fatalf("sticky platform = %s/%s", fp.OS, fp.Arch)
	}

	fp2, _ := g.resolveFingerprint(acc, "Go-http-client/2.0")
	if fp2.UserAgent != "claude-cli/2.1.251 (external, cli)" {
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
			ClientID:       strings.Repeat("cd", 32),
			Entrypoint:     "cli",
			Profile:        "2.1.241",
			UserAgent:      "claude-cli/2.1.241 (external, cli)",
			SDKVersion:     "0.208.0",
			OS:             "Linux",
			Arch:           "arm64",
			Runtime:        "node",
			RuntimeVersion: "v24.3.0",
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
	if gotUA != "claude-cli/2.1.251 (external, cli)" {
		t.Fatalf("upstream UA = %q, want upgraded sticky 2.1.251", gotUA)
	}
	if gotOS != "Linux" || gotArch != "arm64" {
		t.Fatalf("upstream stainless = %s/%s (inbound Windows/x64 must not leak)", gotOS, gotArch)
	}
	if gotSDK != "0.208.0" {
		t.Fatalf("sdk = %q", gotSDK)
	}
}

func TestNewAccountSeedsLinuxX64(t *testing.T) {
	var gotOS, gotArch string
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOS = r.Header.Get("X-Stainless-OS")
		gotArch = r.Header.Get("X-Stainless-Arch")
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	addAccount(t, st, "fresh")
	w := postJSON(t, g, "/v1/messages")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if gotOS != "Linux" || gotArch != "x64" {
		t.Fatalf("new account stainless = %s/%s, want Linux/x64", gotOS, gotArch)
	}
	accs := st.Snapshot()
	if len(accs) != 1 || accs[0].Fingerprint == nil {
		t.Fatal("fingerprint not persisted")
	}
	if accs[0].Fingerprint.Arch != "x64" {
		t.Fatalf("stored arch = %q", accs[0].Fingerprint.Arch)
	}
	if accs[0].Fingerprint.Terminal == "" || accs[0].Fingerprint.Shell == "" || accs[0].Fingerprint.RuntimeVersion == "" {
		t.Fatalf("machine persona incomplete: %+v", accs[0].Fingerprint)
	}
}

func TestTwoNewAccountsGetDifferentPersonasOrDeviceIDs(t *testing.T) {
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"id":"msg_1","content":[{"type":"text","text":"ok"}]}`)
	}))
	a := addAccount(t, st, "a")
	b := addAccount(t, st, "b")
	fa, _ := g.resolveFingerprint(a, "")
	fb, _ := g.resolveFingerprint(b, "")
	if fa.ClientID == fb.ClientID {
		t.Fatal("device_id collision")
	}
	if fa.Arch != "x64" || fb.Arch != "x64" {
		t.Fatalf("new accounts want x64, got %s/%s", fa.Arch, fb.Arch)
	}
	if fa.RuntimeVersion == "" || fa.Terminal == "" || fa.Shell == "" {
		t.Fatalf("persona a incomplete: %+v", fa)
	}
}

func TestExistingArm64FingerprintNotReseededToX64(t *testing.T) {
	var gotArch string
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotArch = r.Header.Get("X-Stainless-Arch")
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	acc := addAccount(t, st, "old")
	_ = st.Update(acc.ID, func(a *store.Account) {
		a.Fingerprint = &store.Fingerprint{
			ClientID: strings.Repeat("ee", 32), Entrypoint: "cli", Profile: "2.1.247",
			UserAgent: "claude-cli/2.1.247 (external, cli)", SDKVersion: "0.208.0",
			OS: "Linux", Arch: "arm64", Runtime: "node", RuntimeVersion: "v24.3.0",
		}
	})
	w := postJSON(t, g, "/v1/messages")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if gotArch != "arm64" {
		t.Fatalf("existing arm64 account reseeded to %q", gotArch)
	}
	fresh, _ := st.Get(acc.ID)
	if fresh.Fingerprint.UserAgent != "claude-cli/2.1.251 (external, cli)" {
		t.Fatalf("UA not one-way upgraded: %q", fresh.Fingerprint.UserAgent)
	}
	if fresh.Fingerprint.Arch != "arm64" {
		t.Fatalf("arch jumped: %q", fresh.Fingerprint.Arch)
	}
}
