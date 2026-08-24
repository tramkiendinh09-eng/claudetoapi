// Package config loads claudetoapi configuration from a JSON file with
// environment-variable overrides.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Mimicry controls request-mimicry behavior.
type Mimicry struct {	// DefaultEntrypoint seeds per-account cc_entrypoint ("cli", "sdk-cli",
	// "claude-vscode"). The entrypoint is paired with a matching system
	// prompt persona, mirroring real client distributions.
	DefaultEntrypoint string `json:"default_entrypoint"`
	// RedactThinking adds the redact-thinking beta (real CLI sends it with
	// experimental betas enabled; off by default because upstream redacts
	// thinking blocks from responses, which breaks some third-party clients).
	RedactThinking bool `json:"redact_thinking"`
	// DispatchHeader sends "anthropic-dispatch-id: v2s" (CLI gate
	// tengu_cedar_lattice / env CLAUDE_CODE_DISPATCH_V2S). Off by default.
	DispatchHeader bool `json:"dispatch_header"`
	// TelemetryBypass reproduces the CLI's first-party background traffic
	// (feature-flag eval pulls + event batching to
	// api.anthropic.com/api/event_logging/v2/batch) so gateway accounts keep
	// a normal telemetry footprint. On by default.
	TelemetryBypass bool `json:"telemetry_bypass"`
	// DisableDatelineNormalization turns off stripping of the steganographic
	// dateline watermark some clients embed when pointed at a non-official
	// base URL. Normalization is on by default.
	DisableDatelineNormalization bool `json:"disable_dateline_normalization"`
	// MaxAttempts bounds per-request account failover attempts.
	MaxAttempts int `json:"max_attempts"`
	// OutputStyle selects a built-in Claude Code output style injected into
	// the system prompt for mimic-mode requests: "" (default), "concise" or
	// "proactive" — same effect as `claude /config outputStyle=…`.
	OutputStyle string `json:"output_style"`
}

// Proxy is a named proxy with geographic identity. Accounts bound to a named
// proxy inherit its timezone and accept-language so the exit IP, the locale
// headers and the dateline date never contradict each other.
type Proxy struct {
	Name     string `json:"name"`
	URL      string `json:"url"`
	Timezone string `json:"timezone,omitempty"` // IANA name, e.g. America/New_York
	Language string `json:"language,omitempty"` // accept-language value, e.g. en-US,en;q=0.9
}

// Config is the root configuration.
type Config struct {
	Listen      string   `json:"listen"`
	AdminKey    string   `json:"admin_key"`
	APIKeys     []string `json:"api_keys"`
	AccountsDir string   `json:"accounts_dir"`
	// DefaultProxyURL applies to all upstream traffic when an account has
	// no dedicated proxy (raw URL or a named pool entry).
	DefaultProxyURL string   `json:"default_proxy_url"`
	Proxies         []Proxy  `json:"proxies"`
	ProfileName     string   `json:"profile"`
	MaxBodyMB       int      `json:"max_body_mb"`
	Mimicry         Mimicry  `json:"mimicry"`
}

func jsonHasKey(raw []byte, key string) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	// Also honor mimicry.telemetry_bypass nesting.
	if v, ok := probe["mimicry"]; ok {
		var inner map[string]json.RawMessage
		if err := json.Unmarshal(v, &inner); err == nil {
			if _, ok := inner[key]; ok {
				return true
			}
		}
	}
	if _, ok := probe[key]; ok {
		return true
	}
	return false
}

// Load reads configPath, applies env overrides and fills defaults.
func Load(configPath string) (*Config, error) {
	cfg := &Config{}
	var rawCfg []byte
	if configPath != "" {
		var err error
		rawCfg, err = os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := json.Unmarshal(rawCfg, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	if v := os.Getenv("CTAPI_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("CTAPI_ADMIN_KEY"); v != "" {
		cfg.AdminKey = v
	}
	if v := os.Getenv("CTAPI_API_KEYS"); v != "" {
		cfg.APIKeys = append(cfg.APIKeys, strings.Split(v, ",")...)
	}
	if v := os.Getenv("CTAPI_PROXY"); v != "" {
		cfg.DefaultProxyURL = v
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8082"
	}
	if cfg.AccountsDir == "" {
		cfg.AccountsDir = "./data"
	}
	if cfg.MaxBodyMB <= 0 {
		cfg.MaxBodyMB = 32
	}
	if cfg.Mimicry.DefaultEntrypoint == "" {
		cfg.Mimicry.DefaultEntrypoint = "cli"
	}
	if cfg.Mimicry.MaxAttempts <= 0 {
		cfg.Mimicry.MaxAttempts = 3
	}
	// Telemetry bypass defaults ON: a real CLI always emits background
	// traffic; opting out is the deliberate choice.
	if !jsonHasKey(rawCfg, "telemetry_bypass") {
		cfg.Mimicry.TelemetryBypass = true
	}
	if cfg.AdminKey == "" {
		return nil, fmt.Errorf("admin_key is required (set it in the config file or CTAPI_ADMIN_KEY)")
	}
	if len(cfg.APIKeys) == 0 {
		return nil, fmt.Errorf("api_keys is required (set it in the config file or CTAPI_API_KEYS)")
	}
	return cfg, nil
}
