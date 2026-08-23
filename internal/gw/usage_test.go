package gw

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanUsageSSE(t *testing.T) {
	var line strings.Builder
	var u usageAcc
	feed := func(s string) usageAcc {
		return scanUsage(line, []byte(s), u)
	}
	u = feed("data: {\"type\":\"message_start\",\"usage\":{\"input_tokens\":4,\"cache_creation_input_tokens\":1200,\"cache_read_input_tokens\":8000,\"output_tokens\":1}}\n")
	u = feed("data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":47}}\n")
	u = feed("data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":130}}\n")
	if u.input != 4 || u.cacheWrite != 1200 || u.cacheRead != 8000 {
		t.Fatalf("input/cache mismatch: %+v", u)
	}
	if u.output != 130 {
		t.Fatalf("output should track the cumulative max, got %d", u.output)
	}
}

func TestLedgerAggregatesAndDayReset(t *testing.T) {
	l := newUsageLedger(filepath.Join(t.TempDir(), "usage_history.json"))
	l.record(UsageRecord{AccountID: 1, Status: 200, Input: 10, Output: 5, CacheWrite: 100, CacheRead: 200})
	l.record(UsageRecord{AccountID: 1, Status: 200, Input: 1, Output: 2, CacheWrite: 0, CacheRead: 50})
	l.record(UsageRecord{AccountID: 1, Status: 429})

	agg := l.aggregates()[1]
	if agg.Total.Reqs != 3 || agg.Total.Errors != 1 {
		t.Fatalf("totals: %+v", agg.Total)
	}
	if agg.Total.Input != 11 || agg.Total.Output != 7 || agg.Total.CacheWrite != 100 || agg.Total.CacheRead != 250 {
		t.Fatalf("token totals: %+v", agg.Total)
	}
	if agg.Today.Reqs != 3 {
		t.Fatalf("today should match total on the same day: %+v", agg.Today)
	}

	// Persist + reload keeps history.
	l.save()
	raw, err := os.ReadFile(l.path)
	if err != nil || len(raw) == 0 {
		t.Fatalf("ledger not persisted")
	}
	l2 := newUsageLedger(l.path)
	if got := l2.aggregates()[1].Total.Reqs; got != 3 {
		t.Fatalf("reload lost records, got %d", got)
	}
	if got := len(l2.recordsFor(0, 100)); got != 3 {
		t.Fatalf("reload lost record log, got %d", got)
	}
	if got := len(l2.recordsFor(1, 100)); got != 3 {
		t.Fatalf("account filter broken, got %d", got)
	}
}
