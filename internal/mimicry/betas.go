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
		// 2.1.247 payload registry: thinking-display-updates rides with
		// interleaved thinking. Dropping it invalidates signatures the CLI
		// already minted under this beta (Invalid `signature` in `thinking`).
		betas = append(betas, profile.BetaThinkingDisplay)
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

// MergeBetas unions the computed CLI beta list with inbound anthropic-beta
// tokens. Identity/capability we always emit stay first; extra tokens the
// real CLI already used to sign thinking blocks are appended. Garbage and
// hop-by-hop junk are ignored.
func MergeBetas(computed, inbound string) string {
	out := splitBetas(computed)
	seen := make(map[string]struct{}, len(out)+8)
	for _, t := range out {
		seen[t] = struct{}{}
	}
	for _, t := range splitBetas(inbound) {
		if !looksLikeBeta(t) {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return strings.Join(out, ",")
}

func splitBetas(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func looksLikeBeta(t string) bool {
	if len(t) < 8 || len(t) > 80 {
		return false
	}
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return strings.Count(t, "-") >= 1
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
