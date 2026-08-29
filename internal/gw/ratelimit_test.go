package gw

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestParse429RetryAfterSeconds(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "42")
	d := Parse429(h, time.Now())
	if d.Reason != "anthropic_429_retry_after" {
		t.Fatalf("reason = %s", d.Reason)
	}
	if d.Cooldown < 41*time.Second || d.Cooldown > 42*time.Second {
		t.Fatalf("cooldown = %s", d.Cooldown)
	}
}

func TestParse429FallbackIs30s(t *testing.T) {
	d := Parse429(http.Header{}, time.Now())
	if d.Reason != "anthropic_429_no_reset_time" || d.Cooldown != 30*time.Second {
		t.Fatalf("got %+v", d)
	}
}

func TestParse429UnifiedWindowWinsOverRetryAfter(t *testing.T) {
	now := time.Now()
	h := http.Header{}
	h.Set("Retry-After", "5")
	h.Set("anthropic-ratelimit-unified-5h-status", "rejected")
	h.Set("anthropic-ratelimit-unified-5h-reset", strconv.FormatInt(now.Add(90*time.Minute).Unix(), 10))
	d := Parse429(h, now)
	if d.Window != "5h" || d.Cooldown < 80*time.Minute {
		t.Fatalf("got %+v", d)
	}
}

func TestEnrich429UsesCachedExhaustedWindow(t *testing.T) {
	now := time.Now()
	d := Parse429(http.Header{}, now)
	five := &WindowStat{Utilization: 1, ResetAt: now.Add(2 * time.Hour)}
	got := Enrich429FromAccount(d, now, five, nil)
	if got.Window != "5h" || got.Reason != "anthropic_5h_window_exhausted_cached" {
		t.Fatalf("got %+v", got)
	}
	if got.Cooldown < time.Hour {
		t.Fatalf("cooldown = %s", got.Cooldown)
	}
}

func TestEnrich429IgnoresHalfUsedWindow(t *testing.T) {
	now := time.Now()
	d := Parse429(http.Header{}, now)
	five := &WindowStat{Utilization: 0.5, ResetAt: now.Add(2 * time.Hour)}
	got := Enrich429FromAccount(d, now, five, nil)
	if got.Reason != "anthropic_429_no_reset_time" {
		t.Fatalf("half-used window must not masquerade as quota: %+v", got)
	}
}
