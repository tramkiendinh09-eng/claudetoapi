// Package profile defines per-CLI-version mimicry profiles.
//
// A profile bundles every upstream-visible value that a specific Claude Code
// CLI release pins together: the UA version, the bundled @anthropic-ai/sdk
// version (X-Stainless-Package-Version), default max_tokens and the beta
// header vocabulary. Real CLI releases lock these values in pairs — e.g.
// claude-cli/2.1.251 bundles SDK 0.208.0 — so a gateway that mixes versions
// from different releases produces client identities that never existed in
// the wild (verified against local claude.exe 2.1.251: VERSION="2.1.251",
// packageVersion "0.208.0", BUILD_TIME 2026-08-28T14:51:38Z, GIT_SHA
// 37534ac596d80cefb02d272f036adba4ba055d2c, native Bun/1.4.1 with Stainless
// still reporting runtime "node").
package profile

import "time"

// Profile is an immutable CLI-version fingerprint bundle.
type Profile struct {
	Name             string
	CLIVersion       string            // e.g. "2.1.247"
	SDKVersion       string            // e.g. "0.208.0" (X-Stainless-Package-Version)
	UserAgent        string            // full User-Agent line
	Stainless        map[string]string // X-Stainless-* values (Lang/OS/Arch/Runtime/RuntimeVersion)
	BuildTime        string            // CLI BUILD_TIME, stamped into telemetry env
	GitSHA           string            // CLI GIT_SHA (diagnostic)
	DefaultMaxTokens int               // CLI default when the request omits max_tokens
	MaxTokensUpper   int               // CLI hard upper bound
	TimeoutHeader    string            // X-Stainless-Timeout default
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

func stainlessNodeLinux(sdk, arch string) map[string]string {
	return map[string]string{
		"X-Stainless-Lang":            "js",
		"X-Stainless-Package-Version": sdk,
		"X-Stainless-OS":              "Linux",
		"X-Stainless-Arch":            arch,
		"X-Stainless-Runtime":         "node",
		"X-Stainless-Runtime-Version": "v24.3.0",
	}
}

// v2_1_241 kept so already-provisioned fingerprints can still resolve the
// profile they were born with. OS/arch/runtime stay sticky on the account;
// only CLI version/UA/SDK ride the upgrade to Default.
var v2_1_241 = &Profile{
	Name:             "2.1.241",
	CLIVersion:       "2.1.241",
	SDKVersion:       "0.208.0",
	UserAgent:        "claude-cli/2.1.241 (external, cli)",
	Stainless:        stainlessNodeLinux("0.208.0", "arm64"),
	BuildTime:        "2026-08-22T22:46:48Z",
	DefaultMaxTokens: 32000,
	MaxTokensUpper:   128000,
	TimeoutHeader:    "600",
}

// v2_1_247 mirrors native claude-cli 2.1.247. The npm optional package is
// @anthropic-ai/claude-code-linux-x64 (os=linux, cpu=x64, libc=glibc) —
// same Bun/1.4.1 payload as win32-x64, Stainless still reports runtime
// "node". Default new identities use linux-x64 to match x86_64 VPS egress;
// already-provisioned arm64 fingerprints stay sticky.
var v2_1_247 = &Profile{
	Name:             "2.1.247",
	CLIVersion:       "2.1.247",
	SDKVersion:       "0.208.0",
	UserAgent:        "claude-cli/2.1.247 (external, cli)",
	Stainless:        stainlessNodeLinux("0.208.0", "x64"),
	BuildTime:        "2026-08-26T05:55:19Z",
	GitSHA:           "89c726188daf6407b6b57bf67d312f2958e5b9f2",
	DefaultMaxTokens: 32000,
	MaxTokensUpper:   128000,
	TimeoutHeader:    "600",
}

// v2_1_251 mirrors native claude-cli 2.1.251 (win32-x64 + linux-x64 bun
// compile, same JS payload). SDK still 0.208.0; thinking-display-updates
// and Vzl salt 59cf53e54c78 are unchanged from 2.1.247.
var v2_1_251 = &Profile{
	Name:             "2.1.251",
	CLIVersion:       "2.1.251",
	SDKVersion:       "0.208.0",
	UserAgent:        "claude-cli/2.1.251 (external, cli)",
	Stainless:        stainlessNodeLinux("0.208.0", "x64"),
	BuildTime:        "2026-08-28T14:51:38Z",
	GitSHA:           "37534ac596d80cefb02d272f036adba4ba055d2c",
	DefaultMaxTokens: 32000,
	MaxTokensUpper:   128000,
	TimeoutHeader:    "600",
}

// Registry of known profiles; Default is used for new identities and for
// one-way version upgrades of existing fingerprints.
var (
	Registry = map[string]*Profile{
		v2_1_241.Name: v2_1_241,
		v2_1_247.Name: v2_1_247,
		v2_1_251.Name: v2_1_251,
	}
	Default = v2_1_251
)

// Lookup returns a named profile, or Default when the name is unknown/empty.
func Lookup(name string) *Profile {
	if p, ok := Registry[name]; ok {
		return p
	}
	return Default
}

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

// DefaultModels mirrors the CLI's advertised model set (2.1.251 registry).
var DefaultModels = []Model{
	{ID: "claude-fable-5", Type: "model", DisplayName: "Claude Fable 5"},
	{ID: "claude-mythos-5", Type: "model", DisplayName: "Claude Mythos 5"},
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
