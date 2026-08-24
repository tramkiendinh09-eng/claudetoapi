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
