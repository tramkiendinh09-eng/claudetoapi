// Package gw implements the request gateway: auth, sticky sessions,
// mimicry application, upstream forwarding, failover and SSE relay.
package gw

import (
	"net/http"
	"strings"

	"claudetoapi/internal/profile"
)

// wireCasing maps lower-case header names to the exact casing observed on
// the wire from real claude-cli traffic (capture-verified). Go canonicalizes
// header keys; upstream sees the difference, so we restore it manually.
var wireCasing = map[string]string{
	"accept":                      "Accept",
	"user-agent":                  "User-Agent",
	"x-stainless-retry-count":     "X-Stainless-Retry-Count",
	"x-stainless-timeout":         "X-Stainless-Timeout",
	"x-stainless-lang":            "X-Stainless-Lang",
	"x-stainless-package-version": "X-Stainless-Package-Version",
	"x-stainless-os":              "X-Stainless-OS",
	"x-stainless-arch":            "X-Stainless-Arch",
	"x-stainless-runtime":         "X-Stainless-Runtime",
	"x-stainless-runtime-version": "X-Stainless-Runtime-Version",
	"anthropic-version":           "anthropic-version",
	"anthropic-beta":              "anthropic-beta",
	"anthropic-dangerous-direct-browser-access": "anthropic-dangerous-direct-browser-access",
	"anthropic-dispatch-id":                      "anthropic-dispatch-id",
	"x-app":                      "x-app",
	"content-type":               "content-type",
	"accept-language":            "accept-language",
	"sec-fetch-mode":             "sec-fetch-mode",
	"x-claude-code-session-id":   "X-Claude-Code-Session-Id",
	"x-client-request-id":        "x-client-request-id",
}

// whitelist are the only client headers passed through for genuine CLI
// traffic. Everything else (hop-by-hop, proxy junk) is dropped.
var whitelist = map[string]bool{
	"accept":                                      true,
	"user-agent":                                  true,
	"x-stainless-retry-count":                     true,
	"x-stainless-timeout":                         true,
	"x-stainless-lang":                            true,
	"x-stainless-package-version":                 true,
	"x-stainless-os":                              true,
	"x-stainless-arch":                            true,
	"x-stainless-runtime":                         true,
	"x-stainless-runtime-version":                 true,
	"anthropic-version":                           true,
	"anthropic-beta":                              true,
	"anthropic-dangerous-direct-browser-access":   true,
	"x-app":                                       true,
	"accept-language":                             true,
	"sec-fetch-mode":                              true,
	"x-claude-code-session-id":                    true,
	"x-client-request-id":                         true,
}

// setHeaderRaw writes a header bypassing Go's canonical-case normalization.
func setHeaderRaw(h http.Header, key, value string) {
	delete(h, key)
	if wk, ok := wireCasing[strings.ToLower(key)]; ok && wk != key {
		delete(h, wk)
	}
	h[key] = []string{value}
}

// HeaderBuildInput describes everything needed to assemble the upstream
// request headers.
type HeaderBuildInput struct {
	Token          string // OAuth access token
	Beta           string // computed anthropic-beta value
	Profile        *profile.Profile
	UserAgent      string // sticky per-account UA
	SDKVersion     string // sticky per-account SDK version
	OS             string // sticky X-Stainless-OS (empty → profile)
	Arch           string // sticky X-Stainless-Arch (empty → profile)
	Runtime        string // sticky X-Stainless-Runtime (empty → profile)
	RuntimeVersion string // sticky X-Stainless-Runtime-Version (empty → profile)
	SessionID      string // X-Claude-Code-Session-Id (stable per conversation)
	ClientReqID    string // x-client-request-id (fresh UUID per request)
	AcceptLanguage string // locale consistent with the exit IP's geography
	Mimic          bool   // synthetic CLI headers; pool accounts always stamp these
	DispatchV2S    bool   // anthropic-dispatch-id: v2s (gate-controlled)
	IsStream       bool
	ClientHeaders  http.Header // original client headers (legacy passthrough path)
}

// BuildUpstreamHeaders assembles the final header set.
func BuildUpstreamHeaders(in HeaderBuildInput) http.Header {
	h := make(http.Header)

	if in.Mimic {
		// Synthetic CLI fingerprint: exactly the header set the CLI sends,
		// nothing from the downstream client.
		setHeaderRaw(h, "authorization", "Bearer "+in.Token)
		setHeaderRaw(h, "anthropic-version", "2023-06-01")
		setHeaderRaw(h, "anthropic-beta", in.Beta)
		setHeaderRaw(h, "anthropic-dangerous-direct-browser-access", "true")
		setHeaderRaw(h, "x-app", "cli")
		setHeaderRaw(h, "User-Agent", in.UserAgent)
		timeout := "600"
		lang, os, arch, runtime, runtimeVer := "js", "Linux", "x64", "node", "v24.3.0"
		if in.Profile != nil {
			timeout = in.Profile.TimeoutHeader
			lang = in.Profile.Stainless["X-Stainless-Lang"]
			os = in.Profile.Stainless["X-Stainless-OS"]
			arch = in.Profile.Stainless["X-Stainless-Arch"]
			runtime = in.Profile.Stainless["X-Stainless-Runtime"]
			runtimeVer = in.Profile.Stainless["X-Stainless-Runtime-Version"]
		}
		if in.OS != "" {
			os = in.OS
		}
		if in.Arch != "" {
			arch = in.Arch
		}
		if in.Runtime != "" {
			runtime = in.Runtime
		}
		if in.RuntimeVersion != "" {
			runtimeVer = in.RuntimeVersion
		}
		for k, v := range map[string]string{
			"X-Stainless-Retry-Count":     "0",
			"X-Stainless-Timeout":         timeout,
			"X-Stainless-Lang":            lang,
			"X-Stainless-Package-Version": in.SDKVersion,
			"X-Stainless-OS":              os,
			"X-Stainless-Arch":            arch,
			"X-Stainless-Runtime":         runtime,
			"X-Stainless-Runtime-Version": runtimeVer,
		} {
			if v != "" {
				setHeaderRaw(h, k, v)
			}
		}
		setHeaderRaw(h, "content-type", "application/json")
		setHeaderRaw(h, "Accept", "application/json") // the CLI sends Accept: application/json even when streaming
		if in.AcceptLanguage != "" {
			setHeaderRaw(h, "accept-language", in.AcceptLanguage)
		}
		if in.DispatchV2S {
			setHeaderRaw(h, "anthropic-dispatch-id", "v2s")
		}
	} else {
		// Genuine CLI traffic: whitelist passthrough, then overwrite auth.
		for key, values := range in.ClientHeaders {
			if !whitelist[strings.ToLower(key)] {
				continue
			}
			wireKey := key
			if wk, ok := wireCasing[strings.ToLower(key)]; ok {
				wireKey = wk
			}
			for _, v := range values {
				h[wireKey] = append(h[wireKey], v)
			}
		}
		if in.Beta != "" {
			setHeaderRaw(h, "anthropic-beta", in.Beta)
		}
		if getRaw(h, "anthropic-version") == "" {
			setHeaderRaw(h, "anthropic-version", "2023-06-01")
		}
		setHeaderRaw(h, "authorization", "Bearer "+in.Token)
		if getRaw(h, "content-type") == "" {
			setHeaderRaw(h, "content-type", "application/json")
		}
	}

	if in.SessionID != "" {
		setHeaderRaw(h, "X-Claude-Code-Session-Id", in.SessionID)
	}
	if in.ClientReqID != "" {
		setHeaderRaw(h, "x-client-request-id", in.ClientReqID)
	}
	// accept-encoding: left unset — the Go transport negotiates gzip and
	// transparently decompresses, which the SSE relay depends on.
	return h
}

// getRaw reads a header trying exact, wire-casing and canonical forms.
func getRaw(h http.Header, key string) string {
	if vals := h[key]; len(vals) > 0 {
		return vals[0]
	}
	if wk, ok := wireCasing[strings.ToLower(key)]; ok && wk != key {
		if vals := h[wk]; len(vals) > 0 {
			return vals[0]
		}
	}
	return h.Get(key)
}
