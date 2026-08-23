package gw

import (
	"encoding/json"
	"log/slog"
	"os"
	"sync"
	"time"
)

// UsageTotals is one aggregate bucket (today or all-time) for one account.
type UsageTotals struct {
	Reqs       int64 `json:"reqs"`
	Errors     int64 `json:"errors"`
	Input      int64 `json:"input"`
	Output     int64 `json:"output"`
	CacheWrite int64 `json:"cache_write"` // cache_creation_input_tokens
	CacheRead  int64 `json:"cache_read"`  // cache_read_input_tokens
}

// UsageRecord is one completed upstream request (success or failure) — the
// per-account request log the console shows.
type UsageRecord struct {
	Time        time.Time `json:"time"`
	AccountID   int64     `json:"account_id"`
	AccountName string    `json:"account_name"`
	Model       string    `json:"model,omitempty"`
	Stream      bool      `json:"stream"`
	Status      int       `json:"status"`
	DurationMS  int64     `json:"duration_ms"`
	Input       int64     `json:"input"`
	Output      int64     `json:"output"`
	CacheWrite  int64     `json:"cache_write"`
	CacheRead   int64     `json:"cache_read"`
}

// UsageAgg pairs today's and all-time totals for one account.
type UsageAgg struct {
	Today UsageTotals `json:"today"`
	Total UsageTotals `json:"total"`
}

const (
	usageRingMax   = 2000 // newest records kept in the ring buffer
	usageSaveEvery = 30 * time.Second
)

// usageLedger tracks per-account usage aggregates plus a bounded per-request
// log, persisted to disk so restarts keep history. All-zero token fields on a
// record mean upstream returned no usage (failed attempt).
type usageLedger struct {
	mu      sync.Mutex
	path    string
	records []UsageRecord
	total   map[int64]UsageTotals
	today   map[int64]UsageTotals
	day     string
	// last successful query (input incl. cache tokens) — telemetry reports
	// per-query numbers like the CLI does.
	lastIn  int64
	lastOut int64
	dirty   bool

	stopOnce sync.Once
	stopCh   chan struct{}
	saveWg   sync.WaitGroup
}

type usagePersist struct {
	Day     string                `json:"day"`
	Total   map[int64]UsageTotals `json:"total"`
	Today   map[int64]UsageTotals `json:"today"`
	Records []UsageRecord         `json:"records"`
}

func newUsageLedger(path string) *usageLedger {
	l := &usageLedger{
		path:   path,
		total:  map[int64]UsageTotals{},
		today:  map[int64]UsageTotals{},
		day:    time.Now().Format("2006-01-02"),
		stopCh: make(chan struct{}),
	}
	l.load()
	return l
}

func (l *usageLedger) load() {
	raw, err := os.ReadFile(l.path)
	if err != nil {
		return
	}
	var p usagePersist
	if err := json.Unmarshal(raw, &p); err != nil {
		slog.Warn("usage_ledger_load_failed", "error", err.Error())
		return
	}
	if p.Total != nil {
		l.total = p.Total
	}
	if p.Day == l.day && p.Today != nil {
		l.today = p.Today
	}
	if len(p.Records) > 0 {
		l.records = p.Records
		if len(l.records) > usageRingMax {
			l.records = l.records[len(l.records)-usageRingMax:]
		}
	}
}

func (l *usageLedger) record(r UsageRecord) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if day := time.Now().Format("2006-01-02"); day != l.day {
		l.day = day
		l.today = map[int64]UsageTotals{}
	}
	l.records = append(l.records, r)
	if len(l.records) > usageRingMax {
		l.records = l.records[len(l.records)-usageRingMax:]
	}
	l.total[r.AccountID] = addTotals(l.total[r.AccountID], r)
	l.today[r.AccountID] = addTotals(l.today[r.AccountID], r)
	if r.Status < 400 {
		l.lastIn = r.Input + r.CacheWrite + r.CacheRead
		l.lastOut = r.Output
	}
	l.dirty = true
}

func addTotals(t UsageTotals, r UsageRecord) UsageTotals {
	t.Reqs++
	if r.Status >= 400 {
		t.Errors++
	}
	t.Input += r.Input
	t.Output += r.Output
	t.CacheWrite += r.CacheWrite
	t.CacheRead += r.CacheRead
	return t
}

func (l *usageLedger) aggregates() map[int64]UsageAgg {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[int64]UsageAgg, len(l.total))
	for id, t := range l.total {
		out[id] = UsageAgg{Today: l.today[id], Total: t}
	}
	return out
}

// recordsFor returns up to limit records newest-first; accountID 0 means all.
func (l *usageLedger) recordsFor(accountID int64, limit int) []UsageRecord {
	if limit <= 0 {
		limit = 100
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]UsageRecord, 0, limit)
	for i := len(l.records) - 1; i >= 0 && len(out) < limit; i-- {
		if accountID != 0 && l.records[i].AccountID != accountID {
			continue
		}
		out = append(out, l.records[i])
	}
	return out
}

func (l *usageLedger) lastUsage() (int64, int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastIn, l.lastOut
}

func (l *usageLedger) startSaver() {
	l.saveWg.Add(1)
	go func() {
		defer l.saveWg.Done()
		t := time.NewTicker(usageSaveEvery)
		defer t.Stop()
		for {
			select {
			case <-l.stopCh:
				l.save()
				return
			case <-t.C:
				l.save()
			}
		}
	}()
}

// close stops the saver and waits for the final flush.
func (l *usageLedger) close() {
	l.stopOnce.Do(func() { close(l.stopCh) })
	l.saveWg.Wait()
}

func (l *usageLedger) save() {
	l.mu.Lock()
	if !l.dirty {
		l.mu.Unlock()
		return
	}
	p := usagePersist{Day: l.day, Total: l.total, Today: l.today, Records: l.records}
	l.dirty = false
	l.mu.Unlock()
	raw, err := json.Marshal(p)
	if err != nil {
		return
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		slog.Warn("usage_ledger_save_failed", "error", err.Error())
		return
	}
	if err := os.Rename(tmp, l.path); err != nil {
		slog.Warn("usage_ledger_save_failed", "error", err.Error())
	}
}
