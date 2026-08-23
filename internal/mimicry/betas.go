package mimicry

import (
	"strings"

	"claudetoapi/internal/profile"
)

// BetaOptions mirrors the conditions under which the 2.1.241 CLI pushes each
// beta token (payload fn G3b + request-time push sites).
type BetaOptions struct {
	// IsHaikuAuxiliary marks haiku requests from non-agentic (auxiliary)
	// query sources — those omit the claude-code beta (G3b: if(!haiku)).
	IsHaikuAuxiliary bool
	// Agentic marks sub-agent queries; they always carry claude-code.
	Agentic bool
	// ThinkingEnabled: interleaved-thinking rides along (all modern claude
	// models are thinking-capable, so this tracks body.thinking presence).
	ThinkingEnabled bool
	// RedactThinking gates redact-thinking (CLI: experimental betas on).
	RedactThinking bool
	// CountTokens switches in token-counting betas for /count_tokens.
	CountTokens bool
	// HasEffort: main-thread queries always push the effort beta (KAE);
	// auxiliary queries never do. We assume main unless known auxiliary.
	Auxiliary bool
	// CacheTTL1h: extended-cache-ttl is pushed only in 1h cache mode.
	CacheTTL1h bool
	// FastMode (body speed=fast on Opus 5 / 4.8).
	FastMode bool
}

// ComputeBetas returns the anthropic-beta header value in the CLI's push
// order: identity betas first, capability betas next, request-time betas last.
func ComputeBetas(model string, o BetaOptions) string {
	isHaiku := strings.Contains(strings.ToLower(model), "haiku")

	var betas []string
	if !isHaiku || o.Agentic {
		betas = append(betas, profile.BetaClaudeCode)
	}
	betas = append(betas, profile.BetaOAuth)
	if o.ThinkingEnabled {
		betas = append(betas, profile.BetaInterleavedThinking)
		if o.RedactThinking {
			betas = append(betas, profile.BetaRedactThinking)
		}
		if o.CountTokens {
			betas = append(betas, profile.BetaTokenCounting)
		}
		betas = append(betas, profile.BetaContextManagement)
	}
	// prompt-caching-scope: first-party default-on.
	betas = append(betas, profile.BetaPromptCachingScope)
	if o.CountTokens {
		betas = append(betas, profile.BetaTokenCounting)
	}
	// Request-time additions (KAE / cache / speed).
	if !o.Auxiliary {
		betas = append(betas, profile.BetaEffort)
	}
	if o.CacheTTL1h {
		betas = append(betas, profile.BetaExtendedCacheTTL)
	}
	if o.FastMode {
		betas = append(betas, profile.BetaFastMode)
	}
	return strings.Join(dedupe(betas), ",")
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
