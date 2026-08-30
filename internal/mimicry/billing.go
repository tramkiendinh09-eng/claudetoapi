// Package mimicry rewrites gateway requests into byte-faithful Claude Code
// CLI traffic. Behavior is derived from the claude.exe 2.1.241 payload
// (local reverse engineering) rather than from any third-party gateway.
package mimicry

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// FingerprintSalt reproduces the CLI's cc_version fingerprint: chars 4/7/20
// of the first user text, salted, hashed, first 3 hex chars (payload fn Vzl).
const FingerprintSalt = "59cf53e54c78"

// ComputeVersionFingerprint implements the CLI algorithm. firstUserText is
// the concatenated text of the first user message; missing indices pad '0'.
func ComputeVersionFingerprint(firstUserText, cliVersion string) string {
	chars := make([]byte, 0, 3)
	for _, i := range []int{4, 7, 20} {
		if i < len(firstUserText) {
			chars = append(chars, firstUserText[i])
		} else {
			chars = append(chars, '0')
		}
	}
	sum := sha256.Sum256([]byte(FingerprintSalt + string(chars) + cliVersion))
	return hex.EncodeToString(sum[:])[:3]
}

// FirstUserText extracts the text of the first user message from a decoded
// /v1/messages body (content as string or block array).
func FirstUserText(body map[string]any) string {
	msgs, ok := body["messages"].([]any)
	if !ok {
		return ""
	}
	for _, m := range msgs {
		msg, ok := m.(map[string]any)
		if !ok || msg["role"] != "user" {
			continue
		}
		switch c := msg["content"].(type) {
		case string:
			return c
		case []any:
			for _, b := range c {
				blk, ok := b.(map[string]any)
				if !ok || blk["type"] != "text" {
					continue
				}
				if t, ok := blk["text"].(string); ok {
					return t
				}
			}
		}
		return ""
	}
	return ""
}

// AttributionOptions describe the billing attribution block (payload fn at
// 0x12445ab7):
//
//	x-anthropic-billing-header: cc_version=V.FP; cc_entrypoint=E;
//	  [cc_workload=W;] [cc_is_subagent=true;] [cc_prev_req=R;] [cc_prompt_id=P;]
type AttributionOptions struct {
	CLIVersion  string
	Fingerprint string // 3-hex suffix
	Entrypoint  string
	Workload    string // e.g. "cron"; empty omits the field
	IsSubagent  bool
	PrevReqID   string // must match ^req_[A-Za-z0-9_-]{1,36}$ or it is dropped
	PromptID    string // must be a UUID or it is dropped
}

const (
	reqIDPattern = "req_" // prefix check plus charset validation below
	uuidLen      = 36
)

// BuildAttribution renders the system[0] billing text exactly as the CLI
// orders its fields. Invalid chain ids are silently omitted, matching the
// CLI's own regex gating.
func BuildAttribution(o AttributionOptions) string {
	var b strings.Builder
	fmt.Fprintf(&b, "x-anthropic-billing-header: cc_version=%s.%s; cc_entrypoint=%s;",
		o.CLIVersion, o.Fingerprint, o.Entrypoint)
	if o.Workload != "" {
		fmt.Fprintf(&b, " cc_workload=%s;", o.Workload)
	}
	if o.IsSubagent {
		b.WriteString(" cc_is_subagent=true;")
	}
	if validReqID(o.PrevReqID) {
		fmt.Fprintf(&b, " cc_prev_req=%s;", o.PrevReqID)
	}
	if validUUID(o.PromptID) {
		fmt.Fprintf(&b, " cc_prompt_id=%s;", o.PromptID)
	}
	return b.String()
}

func validReqID(id string) bool {
	if !strings.HasPrefix(id, reqIDPattern) {
		return false
	}
	rest := id[len(reqIDPattern):]
	if len(rest) == 0 || len(rest) > 32 {
		return false
	}
	for _, r := range rest {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func validUUID(s string) bool {
	if len(s) != uuidLen {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
				return false
			}
		}
	}
	return true
}

// NewRequestID mints a CLI-style request id ("req_" + 22 url-safe chars).
func NewRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	out := make([]byte, 0, len(reqIDPattern)+22)
	out = append(out, reqIDPattern...)
	for _, v := range b {
		out = append(out, alpha[int(v)%len(alpha)])
	}
	return string(out)
}

// NewUUID mints a random v4 UUID.
func NewUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

var ccVersionRe = regexp.MustCompile(`cc_version=\d+\.\d+\.\d+\.[0-9a-fA-F]{3}`)
var ccVersionCapRe = regexp.MustCompile(`cc_version=(\d+\.\d+\.\d+)\.([0-9a-fA-F]{3})`)
var ccEntrypointRe = regexp.MustCompile(`cc_entrypoint=[^;]*`)
var ccEntrypointCapRe = regexp.MustCompile(`cc_entrypoint=([^;]*)`)

// AlignBillingCLIVersion rewrites cc_version in a genuine CLI body so it
// matches the account's sticky CLI version (fingerprint recomputed with
// that version, matching payload fn Vzl). Used when real Claude Code
// traffic is unified onto the pool identity instead of being passed
// through with a foreign version.
func AlignBillingCLIVersion(body map[string]any, cliVersion string) bool {
	if body == nil || strings.TrimSpace(cliVersion) == "" {
		return false
	}
	fp := ComputeVersionFingerprint(FirstUserText(body), cliVersion)
	repl := "cc_version=" + cliVersion + "." + fp
	changed := false
	switch sys := body["system"].(type) {
	case string:
		if next, ok := rewriteBillingVersion(sys, repl); ok {
			body["system"] = next
			changed = true
		}
	case []any:
		for i, b := range sys {
			blk, ok := b.(map[string]any)
			if !ok {
				continue
			}
			t, _ := blk["text"].(string)
			next, ok := rewriteBillingVersion(t, repl)
			if !ok {
				continue
			}
			blk["text"] = next
			sys[i] = blk
			changed = true
		}
	}
	return changed
}

func rewriteBillingVersion(text, repl string) (string, bool) {
	if !strings.Contains(text, "x-anthropic-billing-header:") || !strings.Contains(text, "cc_version=") {
		return text, false
	}
	next := ccVersionRe.ReplaceAllString(text, repl)
	if next == text {
		return text, false
	}
	return next, true
}

// AlignBillingEntrypoint rewrites cc_entrypoint to the account's sticky
// persona so a vscode/agent-sdk body is not paired with cli headers.
func AlignBillingEntrypoint(body map[string]any, entrypoint string) bool {
	if body == nil || strings.TrimSpace(entrypoint) == "" {
		return false
	}
	repl := "cc_entrypoint=" + entrypoint
	changed := false
	switch sys := body["system"].(type) {
	case string:
		if next, ok := rewriteBillingEntrypoint(sys, repl); ok {
			body["system"] = next
			changed = true
		}
	case []any:
		for i, b := range sys {
			blk, ok := b.(map[string]any)
			if !ok {
				continue
			}
			t, _ := blk["text"].(string)
			next, ok := rewriteBillingEntrypoint(t, repl)
			if !ok {
				continue
			}
			blk["text"] = next
			sys[i] = blk
			changed = true
		}
	}
	return changed
}

func rewriteBillingEntrypoint(text, repl string) (string, bool) {
	if !strings.Contains(text, "x-anthropic-billing-header:") || !strings.Contains(text, "cc_entrypoint=") {
		return text, false
	}
	next := ccEntrypointRe.ReplaceAllString(text, repl)
	if next == text {
		return text, false
	}
	return next, true
}

// BillingCLIVersion returns the cc_version triple and 3-hex fingerprint
// from a genuine CLI billing block.
func BillingCLIVersion(body map[string]any) (ver, fp string, ok bool) {
	m := ccVersionCapRe.FindStringSubmatch(billingHeaderText(body))
	if len(m) != 3 {
		return "", "", false
	}
	return m[1], m[2], true
}

// BillingEntrypoint returns cc_entrypoint from a genuine CLI billing block.
func BillingEntrypoint(body map[string]any) string {
	m := ccEntrypointCapRe.FindStringSubmatch(billingHeaderText(body))
	if len(m) != 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func billingHeaderText(body map[string]any) string {
	if body == nil {
		return ""
	}
	switch sys := body["system"].(type) {
	case string:
		if strings.Contains(sys, "x-anthropic-billing-header:") {
			return sys
		}
	case []any:
		for _, b := range sys {
			blk, ok := b.(map[string]any)
			if !ok {
				continue
			}
			t, _ := blk["text"].(string)
			if strings.Contains(t, "x-anthropic-billing-header:") {
				return t
			}
		}
	}
	return ""
}

// HasBillingBlock reports whether a decoded system array already carries a
// genuine CLI billing attribution block (used to detect real CLI traffic
// proxied through upstream gateways that rewrite the User-Agent).
func HasBillingBlock(body map[string]any) bool {
	sys, ok := body["system"].([]any)
	if !ok {
		return false
	}
	for _, b := range sys {
		blk, ok := b.(map[string]any)
		if !ok {
			continue
		}
		t, _ := blk["text"].(string)
		if strings.HasPrefix(t, "x-anthropic-billing-header:") && strings.Contains(t, "cc_entrypoint=") {
			return true
		}
	}
	return false
}

// jsonNumber is a helper for tests/inspectors.
func marshalCompact(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}
