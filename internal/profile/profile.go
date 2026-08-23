// Package profile defines per-CLI-version mimicry profiles.
//
// A profile bundles every upstream-visible value that a specific Claude Code
// CLI release pins together: the UA version, the bundled @anthropic-ai/sdk
// version (X-Stainless-Package-Version), default max_tokens and the beta
// header vocabulary. Real CLI releases lock these values in pairs — e.g.
// claude-cli/2.1.241 bundles SDK 0.208.0 — so a gateway that mixes versions
// from different releases produces client identities that never existed in
// the wild (verified against the local claude.exe 2.1.241 reverse-engineered
// payload: VERSION="2.1.241", packageVersion "0.208.0", max-output defaults
// P3b=32000 / D3b=128000).
package profile

import "time"

// Profile is an immutable CLI-version fingerprint bundle.
type Profile struct {
	Name             string
	CLIVersion       string           // e.g. "2.1.241"
	SDKVersion       string           // e.g. "0.208.0" (X-Stainless-Package-Version)
	UserAgent        string           // full User-Agent line
	Stainless        map[string]string // X-Stainless-* values (Lang/OS/Arch/Runtime/RuntimeVersion)
	DefaultMaxTokens int              // CLI default when the request omits max_tokens
	MaxTokensUpper   int              // CLI hard upper bound
	TimeoutHeader    string           // X-Stainless-Timeout default
}

// Beta token vocabulary observed in the 2.1.241 payload registry.
const (
	BetaClaudeCode          = "claude-code-20250219"
	BetaOAuth               = "oauth-2025-04-20"
	BetaInterleavedThinking = "interleaved-thinking-2025-05-14"
	BetaContext1M           = "context-1m-2025-08-07"
	BetaContextManagement   = "context-management-2025-06-27"
	BetaStructuredOutputs   = "structured-outputs-2025-12-15"
	BetaEffort              = "effort-2025-11-24"
	BetaPromptCachingScope  = "prompt-caching-scope-2026-01-05"
	BetaExtendedCacheTTL    = "extended-cache-ttl-2025-04-11"
	BetaRedactThinking      = "redact-thinking-2026-02-12"
	BetaTokenCounting       = "token-counting-2024-11-01"
	BetaFastMode            = "fast-mode-2026-02-01"
	BetaThinkingTokenCount  = "thinking-token-count-2026-05-13"
	BetaThinkingDisplay     = "thinking-display-updates-2026-08-18"
)

// v2_1_241 mirrors claude-cli 2.1.241 (win32 build c87e2742, 2026-08-22).
var v2_1_241 = &Profile{
	Name:             "2.1.241",
	CLIVersion:       "2.1.241",
	SDKVersion:       "0.208.0",
	UserAgent:        "claude-cli/2.1.241 (external, cli)",
	Stainless: map[string]string{
		"X-Stainless-Lang":            "js",
		"X-Stainless-Package-Version": "0.208.0",
		"X-Stainless-OS":              "Linux",
		"X-Stainless-Arch":            "arm64",
		"X-Stainless-Runtime":         "node",
		"X-Stainless-Runtime-Version": "v24.3.0",
	},
	DefaultMaxTokens: 32000,
	MaxTokensUpper:   128000,
	TimeoutHeader:    "600",
}

// Registry of known profiles; Default is used for new identities.
var (
	Registry = map[string]*Profile{
		v2_1_241.Name: v2_1_241,
	}
	Default = v2_1_241
)

// FingerprintSalt is the CLI's cc_version fingerprint salt (payload constant
// OAE, function Vzl: sha256(salt + chars[4,7,20] + version)[:3]).
const FingerprintSalt = "59cf53e54c78"

// Now is injectable for tests.
var Now = time.Now

// Model is one advertised model row.
type Model struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name"`
}

// DefaultModels mirrors the CLI's advertised model set (2.1.241 registry).
var DefaultModels = []Model{
	{ID: "claude-fable-5", Type: "model", DisplayName: "Claude Fable 5"},
	{ID: "claude-opus-5", Type: "model", DisplayName: "Claude Opus 5"},
	{ID: "claude-opus-4-8", Type: "model", DisplayName: "Claude Opus 4.8"},
	{ID: "claude-opus-4-7", Type: "model", DisplayName: "Claude Opus 4.7"},
	{ID: "claude-opus-4-6", Type: "model", DisplayName: "Claude Opus 4.6"},
	{ID: "claude-opus-4-5", Type: "model", DisplayName: "Claude Opus 4.5"},
	{ID: "claude-sonnet-5", Type: "model", DisplayName: "Claude Sonnet 5"},
	{ID: "claude-sonnet-4-6", Type: "model", DisplayName: "Claude Sonnet 4.6"},
	{ID: "claude-sonnet-4-5", Type: "model", DisplayName: "Claude Sonnet 4.5"},
	{ID: "claude-haiku-4-5", Type: "model", DisplayName: "Claude Haiku 4.5"},
}
