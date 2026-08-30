package mimicry

import (
	"bytes"
	"strings"
	"testing"
)

func TestXXH64EmptySeed0(t *testing.T) {
	got := xxh64(nil, 0)
	if got != 0xEF46DB3751D8E999 {
		t.Fatalf("xxh64 empty seed0 = %016X", got)
	}
}

func TestBuildAttributionIncludesCCHPlaceholder(t *testing.T) {
	at := BuildAttribution(AttributionOptions{
		CLIVersion: "2.1.251", Fingerprint: "abc", Entrypoint: "cli",
	})
	if !strings.Contains(at, "cc_entrypoint=cli; cch=00000;") {
		t.Fatalf("placeholder order wrong: %s", at)
	}
}

func TestSealCCHFillsPlaceholderAndIsStable(t *testing.T) {
	body := map[string]any{
		"model":      "claude-opus-5",
		"max_tokens": 64,
		"messages":   []any{map[string]any{"role": "user", "content": "hi"}},
		"system": []any{
			map[string]any{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.251.abc; cc_entrypoint=cli;"},
		},
	}
	EnsureCCHPlaceholder(body)
	raw, err := EncodeBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("cch=00000")) {
		t.Fatalf("placeholder missing: %s", raw)
	}
	a, err := SealCCH(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealCCH(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(a, []byte("cch=00000")) {
		t.Fatal("placeholder survived seal")
	}
	if !bytes.Equal(a, b) {
		t.Fatal("cch not stable")
	}
	if !bytes.Contains(a, []byte(`"cch=`)) && !bytes.Contains(a, []byte("cch=")) {
		t.Fatalf("sealed body missing cch: %s", a)
	}
}

func TestEnsureCCHPlaceholderInsertsAfterEntrypoint(t *testing.T) {
	body := map[string]any{
		"system": []any{
			map[string]any{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.251.abc; cc_entrypoint=cli; cc_prompt_id=11111111-1111-4111-8111-111111111111;"},
		},
	}
	EnsureCCHPlaceholder(body)
	got := body["system"].([]any)[0].(map[string]any)["text"].(string)
	want := "cc_entrypoint=cli; cch=00000; cc_prompt_id="
	if !strings.Contains(got, want) {
		t.Fatalf("insert order: %s", got)
	}
}
