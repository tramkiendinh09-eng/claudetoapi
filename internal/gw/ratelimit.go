package gw

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RateLimitDecision is the outcome of parsing upstream rate-limit signals.
type RateLimitDecision struct {
	Cooldown time.Duration // 0 = do not cooldown
	Reason   string
	Window   string // "5h" | "7d" | "7d_oi" | "" (unknown/no headers)
}

// fallback429Cooldown is applied to Anthropic 429s that carry no reset
// headers — those are typically third-party-lane rejections rather than real
// quota exhaustion, so a long cooldown would waste the account.
const fallback429Cooldown = 5 * time.Second

// Parse429 inspects Anthropic's unified rate-limit headers:
//
//	anthropic-ratelimit-unified-{5h,7d,7d_oi}-(reset|utilization|surpassed-threshold|status)
//
// It prefers the window that actually rejected the request and returns its
// reset deadline; headerless 429s get the short fallback.
func Parse429(h http.Header, now time.Time) RateLimitDecision {
	for _, window := range []string{"7d", "5h"} {
		if rejected(h, window) || exceeded(h, window) {
			if reset, ok := resetAt(h, window, now); ok {
				d := time.Until(reset)
				if d > 0 {
					return RateLimitDecision{Cooldown: d, Reason: "anthropic_" + window + "_window_exhausted", Window: window}
				}
			}
		}
	}
	// Aggregate header fallback (older deployments).
	if raw := strings.TrimSpace(h.Get("anthropic-ratelimit-unified-reset")); raw != "" {
		if ts, err := strconv.ParseInt(raw, 10, 64); err == nil {
			if ts > 1e11 {
				ts /= 1000
			}
			reset := time.Unix(ts, 0)
			if d := reset.Sub(now); d > 0 {
				return RateLimitDecision{Cooldown: d, Reason: "anthropic_unified_reset", Window: "unified"}
			}
		}
	}
	return RateLimitDecision{Cooldown: fallback429Cooldown, Reason: "anthropic_429_no_reset_time", Window: ""}
}

// ParseModelWindow handles per-model windows (7d_oi on Fable): returns a
// model-scoped cooldown decision (Window "7d_oi").
func ParseModelWindow(h http.Header, now time.Time) (RateLimitDecision, bool) {
	const w = "7d_oi"
	if !rejected(h, w) && !exceeded(h, w) {
		return RateLimitDecision{}, false
	}
	reset, ok := resetAt(h, w, now)
	if !ok {
		raw := strings.TrimSpace(h.Get("anthropic-ratelimit-unified-reset"))
		if ts, err := strconv.ParseInt(raw, 10, 64); err == nil {
			if ts > 1e11 {
				ts /= 1000
			}
			reset = time.Unix(ts, 0)
			ok = true
		}
	}
	if !ok {
		return RateLimitDecision{}, false
	}
	if d := reset.Sub(now); d > 0 {
		return RateLimitDecision{Cooldown: d, Reason: "anthropic_7d_oi_window_exhausted", Window: w}, true
	}
	return RateLimitDecision{}, false
}

func rejected(h http.Header, window string) bool {
	return strings.EqualFold(strings.TrimSpace(h.Get("anthropic-ratelimit-unified-"+window+"-status")), "rejected")
}

func exceeded(h http.Header, window string) bool {
	prefix := "anthropic-ratelimit-unified-" + window + "-"
	if st := strings.TrimSpace(h.Get(prefix + "surpassed-threshold")); strings.EqualFold(st, "true") {
		return true
	}
	if util := strings.TrimSpace(h.Get(prefix + "utilization")); util != "" {
		if f, err := strconv.ParseFloat(util, 64); err == nil && f >= 1.0-1e-9 {
			return true
		}
	}
	return false
}

func resetAt(h http.Header, window string, now time.Time) (time.Time, bool) {
	raw := strings.TrimSpace(h.Get("anthropic-ratelimit-unified-" + window + "-reset"))
	if raw == "" {
		return time.Time{}, false
	}
	ts, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	if ts > 1e11 {
		ts /= 1000
	}
	reset := time.Unix(ts, 0)
	maxAge := 8 * 24 * time.Hour
	if window == "5h" {
		maxAge = 6 * time.Hour
	}
	if !reset.After(now) || reset.After(now.Add(maxAge)) {
		return time.Time{}, false
	}
	return reset, true
}

// SessionWindowFromHeaders extracts the 5h window reset (used for
// observability; returns zero when absent).
func SessionWindowFromHeaders(h http.Header, now time.Time) (time.Time, bool) {
	return resetAt(h, "5h", now)
}

// WindowStat is one rate-limit window snapshot harvested from response
// headers (present on success responses too, not only 429s).
type WindowStat struct {
	Utilization float64   `json:"utilization"` // 0..1
	ResetAt     time.Time `json:"reset_at"`
}

// WindowsFromHeaders harvests the 5h and 7d unified rate-limit windows from
// any upstream response. Nil when the window's headers are absent.
func WindowsFromHeaders(h http.Header, now time.Time) (five, seven *WindowStat) {
	if u, ok := utilizationOf(h, "5h"); ok {
		if r, ok2 := resetAt(h, "5h", now); ok2 {
			five = &WindowStat{Utilization: u, ResetAt: r}
		}
	}
	if u, ok := utilizationOf(h, "7d"); ok {
		if r, ok2 := resetAt(h, "7d", now); ok2 {
			seven = &WindowStat{Utilization: u, ResetAt: r}
		}
	}
	return five, seven
}

func utilizationOf(h http.Header, window string) (float64, bool) {
	raw := strings.TrimSpace(h.Get("anthropic-ratelimit-unified-" + window + "-utilization"))
	if raw == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || f < 0 {
		return 0, false
	}
	if f > 1 {
		f = 1
	}
	return f, true
}
