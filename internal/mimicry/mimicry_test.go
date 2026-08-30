package mimicry

import (
	"strings"
	"testing"
)

func TestComputeVersionFingerprintMatchesCLI(t *testing.T) {
	// Reference vector: first-user-text "hello world from claudetoapi!",
	// version 2.1.241. Expected value computed by re-implementing the
	// payload algorithm independently in the test.
	got := ComputeVersionFingerprint("hello world from claudetoapi!", "2.1.241")
	if len(got) != 3 {
		t.Fatalf("fingerprint must be 3 hex chars, got %q", got)
	}
	if got == "000" && len("hello world from claudetoapi!") > 20 {
		t.Fatalf("suspicious all-zero fingerprint")
	}
	// Short text pads with '0'.
	got2 := ComputeVersionFingerprint("ab", "2.1.241")
	if got2 == "" {
		t.Fatal("short text must still produce a fingerprint")
	}
}

func TestBuildAttributionChain(t *testing.T) {
	at := BuildAttribution(AttributionOptions{
		CLIVersion:  "2.1.241",
		Fingerprint: "abc",
		Entrypoint:  "cli",
		PrevReqID:   "req_abcdefghij0123456789AB",
		PromptID:    "474107af-f17f-4ffc-a02a-1f017c7ae71f",
	})
	want := "x-anthropic-billing-header: cc_version=2.1.241.abc; cc_entrypoint=cli;" +
		" cc_prev_req=req_abcdefghij0123456789AB; cc_prompt_id=474107af-f17f-4ffc-a02a-1f017c7ae71f;"
	if at != want {
		t.Fatalf("attribution mismatch:\n got %s\nwant %s", at, want)
	}

	// Invalid chain ids are dropped, not emitted.
	noChain := BuildAttribution(AttributionOptions{
		CLIVersion: "2.1.241", Fingerprint: "abc", Entrypoint: "cli",
		PrevReqID: "not-a-req-id", PromptID: "short",
	})
	if strings.Contains(noChain, "cc_prev_req") || strings.Contains(noChain, "cc_prompt_id") {
		t.Fatalf("invalid ids must be omitted: %s", noChain)
	}
}

func TestComputeBetasP0Rules(t *testing.T) {
	// Haiku main-thread requests drop the claude-code beta (G3b rule).
	haiku := ComputeBetas("claude-haiku-4-5", BetaOptions{ThinkingEnabled: true})
	if strings.Contains(haiku, "claude-code-20250219") {
		t.Fatalf("haiku must not carry claude-code beta: %s", haiku)
	}
	// Agentic haiku carries it.
	agentic := ComputeBetas("claude-haiku-4-5", BetaOptions{Agentic: true, ThinkingEnabled: true})
	if !strings.Contains(agentic, "claude-code-20250219") {
		t.Fatalf("agentic haiku must carry claude-code beta: %s", agentic)
	}
	// extended-cache-ttl appears ONLY in 1h mode.
	plain := ComputeBetas("claude-sonnet-4-5", BetaOptions{ThinkingEnabled: true})
	if strings.Contains(plain, "extended-cache-ttl") {
		t.Fatalf("5m caching must not carry extended-cache-ttl: %s", plain)
	}
	with1h := ComputeBetas("claude-sonnet-4-5", BetaOptions{ThinkingEnabled: true, CacheTTL1h: true})
	if !strings.Contains(with1h, "extended-cache-ttl-2025-04-11") {
		t.Fatalf("1h mode must carry extended-cache-ttl: %s", with1h)
	}
	// Redact-thinking is opt-in.
	if strings.Contains(plain, "redact-thinking") {
		t.Fatalf("redact-thinking must default off: %s", plain)
	}
	if !strings.Contains(plain, "thinking-display-updates-2026-08-18") {
		t.Fatalf("thinking requests must carry thinking-display-updates: %s", plain)
	}
	off := ComputeBetas("claude-sonnet-4-5", BetaOptions{})
	if strings.Contains(off, "thinking-display-updates") {
		t.Fatalf("non-thinking requests must not carry thinking-display-updates: %s", off)
	}
	old := ComputeBetas("claude-sonnet-4-5", BetaOptions{ThinkingEnabled: true, CLIVersion: "2.1.226"})
	if strings.Contains(old, "thinking-display-updates") {
		t.Fatalf("2.1.226 must not carry thinking-display-updates: %s", old)
	}
	cur := ComputeBetas("claude-sonnet-4-5", BetaOptions{ThinkingEnabled: true, CLIVersion: "2.1.247"})
	if !strings.Contains(cur, "thinking-display-updates-2026-08-18") {
		t.Fatalf("2.1.247 must carry thinking-display-updates: %s", cur)
	}
}

func TestFreezeBetasKeepsInboundOmitsComputedExtras(t *testing.T) {
	computed := ComputeBetas("claude-opus-5", BetaOptions{ThinkingEnabled: true})
	if !strings.Contains(computed, "thinking-display-updates-2026-08-18") {
		t.Fatalf("computed must still carry display-updates for mimic: %s", computed)
	}
	got := FreezeBetas("claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14", computed)
	if strings.Contains(got, "thinking-display-updates") {
		t.Fatalf("FreezeBetas must not inject display-updates the client omitted: %s", got)
	}
	if !strings.Contains(got, "claude-code-20250219") || !strings.Contains(got, "oauth-2025-04-20") {
		t.Fatalf("identity betas dropped: %s", got)
	}
	if fallback := FreezeBetas("garbage SPACE", computed); fallback != computed {
		t.Fatalf("junk inbound must fall back to computed, got %s", fallback)
	}
}

func TestMergeBetasKeepsCLIExtras(t *testing.T) {
	base := ComputeBetas("claude-opus-5", BetaOptions{ThinkingEnabled: true})
	got := MergeBetas(base, "claude-code-20250219,thinking-display-updates-2026-08-18,task-budgets-2026-03-13,garbage SPACE")
	if !strings.Contains(got, "task-budgets-2026-03-13") {
		t.Fatalf("inbound CLI extra beta dropped: %s", got)
	}
	if strings.Contains(got, "garbage") || strings.Contains(got, "SPACE") {
		t.Fatalf("junk inbound beta leaked: %s", got)
	}
}

func TestStripThinkingBlocks(t *testing.T) {
	body := map[string]any{
		"messages": []any{
			map[string]any{"role": "user", "content": "hi"},
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "thinking", "thinking": "secret", "signature": "sig"},
				map[string]any{"type": "text", "text": "ok"},
				map[string]any{"type": "redacted_thinking", "data": "xx"},
			}},
		},
	}
	if !HasSignedThinking(body) {
		t.Fatal("expected signed thinking")
	}
	if !StripThinkingBlocks(body) {
		t.Fatal("expected strip")
	}
	if HasSignedThinking(body) {
		t.Fatal("thinking survived strip")
	}
	blocks := body["messages"].([]any)[1].(map[string]any)["content"].([]any)
	if len(blocks) != 1 || blocks[0].(map[string]any)["text"] != "ok" {
		t.Fatalf("kept blocks = %#v", blocks)
	}
}

func TestEncodeBodyDoesNotHTMLEscape(t *testing.T) {
	raw, err := EncodeBody(map[string]any{"text": "a < b & c > d"})
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if strings.Contains(s, `\u003c`) || strings.Contains(s, `\u003e`) || strings.Contains(s, `\u0026`) {
		t.Fatalf("HTML escaped: %s", s)
	}
	if !strings.Contains(s, `a < b & c > d`) {
		t.Fatalf("raw brackets missing: %s", s)
	}
}

func TestTransformP0Fixes(t *testing.T) {
	body := map[string]any{
		"model":    "claude-sonnet-4-5",
		"messages": []any{map[string]any{"role": "user", "content": "hi there"}},
		"system":   "You are a helpful assistant.",
		"thinking": map[string]any{"type": "enabled", "budget_tokens": float64(999999)},
		"stream":   true,
	}
	Transform(body, TransformOptions{
		Profile:     ProfileView{CLIVersion: "2.1.241", DefaultMaxTokens: 32000, MaxTokensUpper: 128000},
		Persona:     PersonaCLI,
		Attribution: "x-anthropic-billing-header: cc_version=2.1.241.abc; cc_entrypoint=cli;",
		ClientID:    strings.Repeat("a", 64),
		SessionID:   "474107af-f17f-4ffc-a02a-1f017c7ae71f",
	})

	if mt := body["max_tokens"].(int); mt != 32000 {
		t.Fatalf("max_tokens must default to 32000 (P0-1), got %v", body["max_tokens"])
	}
	if _, hasTemp := body["temperature"]; hasTemp {
		t.Fatalf("temperature must never be injected (P0-2)")
	}
	thinking := body["thinking"].(map[string]any)
	if bt := thinking["budget_tokens"].(int); bt != 31999 {
		t.Fatalf("budget must clamp to max_tokens-1, got %v", thinking["budget_tokens"])
	}
	if thinking["display"] != "omitted" {
		t.Fatalf("thinking.display must be set, got %v", thinking["display"])
	}
	if _, ok := body["context_management"]; !ok {
		t.Fatal("thinking must bring context_management")
	}
	sys := body["system"].([]any)
	if len(sys) != 3 {
		t.Fatalf("system must be the 3-block CLI stack, got %d blocks", len(sys))
	}
	// Blocks 1 and 2 carry bare ephemeral cache_control (P0-3): no ttl key.
	for i := 1; i <= 2; i++ {
		blk := sys[i].(map[string]any)
		cc := blk["cache_control"].(map[string]any)
		if cc["type"] != "ephemeral" {
			t.Fatalf("block %d cache_control.type must be ephemeral", i)
		}
		if _, hasTTL := cc["ttl"]; hasTTL {
			t.Fatalf("block %d cache_control must NOT carry ttl in default mode (P0-3)", i)
		}
	}
	if _, hasTTL := sys[0].(map[string]any)["cache_control"]; hasTTL {
		t.Fatal("billing block must not carry cache_control")
	}
	// Original system moved into messages head.
	msgs := body["messages"].([]any)
	if len(msgs) < 3 {
		t.Fatalf("original system must be injected as leading messages, got %d", len(msgs))
	}
	first := msgs[0].(map[string]any)
	if first["role"] != "user" {
		t.Fatal("injected instruction message must be a user message")
	}
	// user_id in 2.1.x JSON format.
	meta := body["metadata"].(map[string]any)
	uid := meta["user_id"].(string)
	if !strings.Contains(uid, `"device_id"`) || !strings.Contains(uid, `"session_id"`) {
		t.Fatalf("user_id must use the JSON form: %s", uid)
	}
}

func TestNormalizeDateline(t *testing.T) {
	watermarked := "Today’s date is 2026/08/23." // U+2019 apostrophe, slash separators
	body := map[string]any{
		"system":   watermarked,
		"messages": []any{},
	}
	if !NormalizeDateline(body) {
		t.Fatal("watermark must be detected")
	}
	if body["system"] != "Today's date is 2026-08-23." {
		t.Fatalf("dateline must canonicalize to ASCII+hyphen, got %q", body["system"])
	}
	// User prose with a date stays untouched.
	body2 := map[string]any{
		"system":   "plain",
		"messages": []any{map[string]any{"role": "user", "content": "Today’s date is 2026/08/23. wrote the report"}},
	}
	if NormalizeDateline(body2) {
		t.Fatal("message text outside <system-reminder> must not be touched")
	}
}

func TestBillingCLIVersionParse(t *testing.T) {
	body := map[string]any{
		"system": []any{
			map[string]any{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.226.abc; cc_entrypoint=cli;"},
		},
	}
	ver, fp, ok := BillingCLIVersion(body)
	if !ok || ver != "2.1.226" || fp != "abc" {
		t.Fatalf("ver=%s fp=%s ok=%v", ver, fp, ok)
	}
	if BillingEntrypoint(body) != "cli" {
		t.Fatalf("entrypoint=%s", BillingEntrypoint(body))
	}
}

func TestAlignBillingCLIVersion(t *testing.T) {
	first := "hello world from claudetoapi!"
	wantFP := ComputeVersionFingerprint(first, "2.1.247")
	body := map[string]any{
		"messages": []any{map[string]any{"role": "user", "content": first}},
		"system": []any{
			map[string]any{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.246.abc; cc_entrypoint=cli;"},
			map[string]any{"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."},
		},
	}
	if !AlignBillingCLIVersion(body, "2.1.247") {
		t.Fatal("expected billing rewrite")
	}
	got := body["system"].([]any)[0].(map[string]any)["text"].(string)
	want := "x-anthropic-billing-header: cc_version=2.1.247." + wantFP + "; cc_entrypoint=cli;"
	if got != want {
		t.Fatalf("billing not aligned:\n got %s\nwant %s", got, want)
	}
	ident := body["system"].([]any)[1].(map[string]any)["text"].(string)
	if ident != "You are Claude Code, Anthropic's official CLI for Claude." {
		t.Fatal("non-billing system block must stay intact")
	}
	if AlignBillingCLIVersion(body, "2.1.247") {
		t.Fatal("second align with same version must be a no-op")
	}
}

func TestAlignBillingEntrypoint(t *testing.T) {
	body := map[string]any{
		"system": []any{
			map[string]any{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.247.abc; cc_entrypoint=claude-vscode; cc_prompt_id=11111111-1111-4111-8111-111111111111;"},
		},
	}
	if !AlignBillingEntrypoint(body, "cli") {
		t.Fatal("expected entrypoint rewrite")
	}
	got := body["system"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(got, "cc_entrypoint=cli;") || strings.Contains(got, "claude-vscode") {
		t.Fatalf("entrypoint not aligned: %s", got)
	}
}

func TestIsClaudeCodeClient(t *testing.T) {
	body := map[string]any{
		"metadata": map[string]any{"user_id": `{}`},
	}
	if !IsClaudeCodeClient("claude-cli/2.1.241 (external, cli)", body) {
		t.Fatal("claude-cli UA with user_id must be detected")
	}
	if IsClaudeCodeClient("opencode/1.0", body) {
		t.Fatal("non-CLI UA must not be detected")
	}
}

func TestOutputStyleInjection(t *testing.T) {
	body := map[string]any{
		"model":      "claude-sonnet-4-5-20250929",
		"max_tokens": 100,
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
	}
	Transform(body, TransformOptions{
		Persona:     PersonaCLI,
		Attribution: "x-anthropic-billing-header: cc_version=2.1.241.abc",
		ClientID:    strings.Repeat("a", 64),
		SessionID:   "11111111-1111-1111-1111-111111111111",
		OutputStyle: "concise",
	})
	blocks, _ := body["system"].([]any)
	if len(blocks) != 4 { // attribution + identity + style + expansion
		t.Fatalf("concise style must add one block, got %d", len(blocks))
	}
	ident := blocks[1].(map[string]any)["text"].(string)
	if !strings.Contains(ident, `your "Output Style" below`) {
		t.Fatalf("identity line not swapped: %q", ident[:80])
	}
	style := blocks[2].(map[string]any)["text"].(string)
	if !strings.HasPrefix(style, "# Output Style: Concise\n") {
		t.Fatalf("style section header wrong: %q", style[:40])
	}
	if !strings.Contains(style, "Lead with the result") || !strings.Contains(style, "Concise Style Active") {
		t.Fatal("style section missing the verbatim payload text")
	}
}

func TestOutputStyleDefaultUnchanged(t *testing.T) {
	body := map[string]any{
		"model":      "claude-sonnet-4-5-20250929",
		"max_tokens": 100,
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
	}
	Transform(body, TransformOptions{
		Persona:     PersonaCLI,
		Attribution: "x-anthropic-billing-header: cc_version=2.1.241.abc",
		ClientID:    strings.Repeat("a", 64),
		SessionID:   "11111111-1111-1111-1111-111111111111",
	})
	blocks, _ := body["system"].([]any)
	if len(blocks) != 3 {
		t.Fatalf("default style must keep 3 blocks, got %d", len(blocks))
	}
	if got := blocks[1].(map[string]any)["text"].(string); got != PersonaCLI.Identity {
		t.Fatal("default identity must stay the persona identity")
	}
}

func TestStyleFor(t *testing.T) {
	if StyleFor("") != nil || StyleFor("nope") != nil {
		t.Fatal("empty/unknown keys must resolve to nil")
	}
	c := StyleFor("Concise") // case-insensitive
	if c == nil || c.Name != "Concise" {
		t.Fatal("concise style must resolve case-insensitively")
	}
	if !ValidStyleKey("") || !ValidStyleKey("concise") || ValidStyleKey("nope") {
		t.Fatal("ValidStyleKey matrix broken")
	}
}

func TestTransformCountTokensStripsExtras(t *testing.T) {
	body := map[string]any{
		"model":       "claude-opus-5",
		"max_tokens":  64,
		"stream":      true,
		"temperature": 0.2,
		"messages":    []any{map[string]any{"role": "user", "content": "hi"}},
	}
	Transform(body, TransformOptions{
		Profile:     ProfileView{CLIVersion: "2.1.247", DefaultMaxTokens: 32000, MaxTokensUpper: 128000},
		Persona:     PersonaCLI,
		ClientID:    strings.Repeat("ab", 32),
		SessionID:   "11111111-1111-4111-8111-111111111111",
		CountTokens: true,
	})
	if _, ok := body["max_tokens"]; ok {
		t.Fatal("count_tokens must not forward max_tokens")
	}
	if _, ok := body["stream"]; ok {
		t.Fatal("count_tokens must not forward stream")
	}
	if _, ok := body["temperature"]; ok {
		t.Fatal("count_tokens must not forward temperature")
	}
	if _, ok := body["metadata"]; ok {
		t.Fatal("count_tokens must not forward metadata")
	}
}
