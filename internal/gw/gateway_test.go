package gw

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"claudetoapi/internal/config"
	"claudetoapi/internal/store"
)

// newTestGateway builds a gateway pointed at a fake upstream served by h.
func newTestGateway(t *testing.T, h http.Handler) (*Gateway, *httptest.Server, *store.Store) {
	t.Helper()
	up := httptest.NewServer(h)
	t.Cleanup(up.Close)
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AccountsDir: dir, MaxBodyMB: 4}
	cfg.Mimicry.MaxAttempts = 3
	g := New(cfg, st)
	g.upstreamBase = up.URL
	// The fake upstream is plain HTTP: route the ordered transport at it
	// directly instead of through the TLS fingerprint dialer.
	overrideUpstreamTransport(up.URL)
	t.Cleanup(clearUpstreamOverrides)
	return g, up, st
}

// overrideUpstreamTransport swaps the transport pool so requests to base URL
// host use a fresh plain-HTTP transport.
func overrideUpstreamTransport(rawURL string) {
	transportPoolMu.Lock()
	defer transportPoolMu.Unlock()
	transportPool[rawURL] = &OrderedTransport{proxyURL: "", idle: map[string][]*pooledConn{}}
}

func clearUpstreamOverrides() {
	transportPoolMu.Lock()
	defer transportPoolMu.Unlock()
	transportPool = map[string]*OrderedTransport{}
}

func addAccount(t *testing.T, st *store.Store, name string) *store.Account {
	t.Helper()
	acc := &store.Account{Name: name, Credentials: store.Credentials{
		AccessToken: "test-token",
		ExpiresAt:   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}}
	if err := st.Add(acc); err != nil {
		t.Fatal(err)
	}
	return acc
}

func postJSON(t *testing.T, g *Gateway, path string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"model":"claude-sonnet-4-5-20250929","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	w := httptest.NewRecorder()
	g.handleMessages(w, req, strings.HasSuffix(path, "count_tokens"))
	return w
}

func TestForwardNonStream(t *testing.T) {
	var gotPath string
	var gotAuth string
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"model":"claude-sonnet-4-5-20250929","stop_reason":"end_turn","usage":{"input_tokens":11,"output_tokens":7,"cache_creation_input_tokens":100,"cache_read_input_tokens":200}}`)
	}))
	addAccount(t, st, "a1")

	w := postJSON(t, g, "/v1/messages")
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if gotPath != "/v1/messages" {
		t.Fatalf("upstream path = %s", gotPath)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") {
		t.Fatalf("missing bearer: %q", gotAuth)
	}
	rec := g.ledger.recordsFor(0, 10)[0]
	if rec.Status != 200 || rec.Input != 11 || rec.Output != 7 || rec.CacheWrite != 100 || rec.CacheRead != 200 {
		t.Fatalf("ledger record wrong: %+v", rec)
	}
}

func TestForwardCountTokensUsesOwnEndpoint(t *testing.T) {
	var gotPath string
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprint(w, `{"input_tokens":1234}`)
	}))
	addAccount(t, st, "a1")

	w := postJSON(t, g, "/v1/messages/count_tokens")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "1234") {
		t.Fatalf("count_tokens relay failed: %d %s", w.Code, w.Body.String())
	}
	if gotPath != "/v1/messages/count_tokens" {
		t.Fatalf("count_tokens hit wrong upstream path: %s", gotPath)
	}
	rec := g.ledger.recordsFor(0, 10)[0]
	if rec.Input != 1234 {
		t.Fatalf("count_tokens not ledgered: %+v", rec)
	}
}

func TestForwardSSEUsage(t *testing.T) {
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":5,\"cache_read_input_tokens\":500,\"output_tokens\":1}}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"text\"},\"usage\":{\"input_tokens\":5,\"cache_read_input_tokens\":500}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":42}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"message_stop\"}\n\n")
	}))
	addAccount(t, st, "a1")

	body := `{"model":"claude-sonnet-4-5-20250929","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	w := httptest.NewRecorder()
	g.handleMessages(w, req, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "message_delta") {
		t.Fatalf("sse relay failed: %d %s", w.Code, w.Body.String())
	}
	rec := g.ledger.recordsFor(0, 10)[0]
	if rec.Input != 5 || rec.CacheRead != 500 || rec.Output != 42 {
		t.Fatalf("sse usage wrong: %+v", rec)
	}
}

func Test429CooldownAndFailover(t *testing.T) {
	calls := 0
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("retry-after", "600")
			w.WriteHeader(429)
			fmt.Fprint(w, `{"type":"error","error":{"type":"rate_limit_error"}}`)
			return
		}
		fmt.Fprint(w, `{"id":"msg_2","type":"message","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	addAccount(t, st, "a1")
	addAccount(t, st, "a2")

	w := postJSON(t, g, "/v1/messages")
	if w.Code != 200 {
		t.Fatalf("failover failed: %d %s", w.Code, w.Body.String())
	}
	if calls != 2 {
		t.Fatalf("expected 2 upstream calls, got %d", calls)
	}
	// Whichever account ate the 429 must now be cooling until its window.
	cooling := 0
	for _, acc := range st.Snapshot() {
		if acc.RateLimitedUntil != nil && time.Until(*acc.RateLimitedUntil) > 0 {
			cooling++
		}
	}
	if cooling != 1 {
		t.Fatalf("expected exactly 1 cooling account after 429, got %d", cooling)
	}
}

func TestOverloadedRetryAfter(t *testing.T) {
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
	}))
	acc := addAccount(t, st, "a1")
	until := time.Now().Add(90 * time.Second)
	_ = st.Update(acc.ID, func(a *store.Account) { a.RateLimitedUntil = &until })

	w := postJSON(t, g, "/v1/messages")
	if w.Code != 503 {
		t.Fatalf("want 503, got %d", w.Code)
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Fatal("missing Retry-After on 503")
	} else if n := parseInt(ra); n <= 0 || n > 91 {
		t.Fatalf("Retry-After out of range: %s", ra)
	}
}

func TestNoAccountsIs503(t *testing.T) {
	g, _, _ := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	w := postJSON(t, g, "/v1/messages")
	if w.Code != 503 {
		t.Fatalf("want 503, got %d", w.Code)
	}
}

func parseInt(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

func TestPerAccountTokenLocks(t *testing.T) {
	g := &Gateway{tokenLock: map[int64]*sync.Mutex{}}
	a := g.lockAccount(1)
	b := g.lockAccount(2)
	a.Lock()
	if b.TryLock() == false {
		t.Fatal("lock for account 2 should be independent of account 1")
	}
	b.Unlock()
	a.Unlock()
	// same account returns the same lock
	if g.lockAccount(1) != a {
		t.Fatal("lock identity must be stable per account")
	}
}

func TestSecureHasKey(t *testing.T) {
	if !secureHasKey("k1", []string{"k1", "k2"}) {
		t.Fatal("valid key rejected")
	}
	if secureHasKey("k1", []string{}) || secureHasKey("", []string{"k1"}) || secureHasKey("k1", []string{"k2"}) {
		t.Fatal("invalid key accepted")
	}
	if secureHasKey("x", []string{""}) {
		t.Fatal("empty expected key must reject")
	}
}

func TestClassifyErrorBody(t *testing.T) {
	cases := []struct {
		body string
		want ErrorClass
	}{
		// geo-blocked 403: proxy problem, must NOT read as banned
		{`{"error":{"message":"Access to Anthropic models is not allowed from unsupported countries, regions, or territories"}}`, ErrGeoBlocked},
		{"Your IP is not authorized to make this request", ErrGeoBlocked},
		// banned: permanent disable
		{"Your access has been disabled for a suspected violation of our Usage Policy", ErrBanned},
		{"This organization has been disabled.", ErrBanned},
		// model access: failover, keep account
		{`{"error":{"message":"claude-opus-4-5 does not have access to model"}}`, ErrModelAccess},
		{"is in limited preview and is not available on this account", ErrModelAccess},
		// billing: long cooldown
		{"Your credit balance is too low", ErrBilling},
		{"Your project has exceeded its monthly spending cap", ErrBilling},
		// unrelated text stays unknown
		{"invalid request: max_tokens too large", ErrUnknown},
		{"", ErrUnknown},
	}
	for _, c := range cases {
		if got := classifyErrorBody(c.body); got != c.want {
			t.Errorf("classify(%q) = %v, want %v", truncateStr(c.body, 50), got, c.want)
		}
	}
}

func TestGeoBlocked403DoesNotDisableAccount(t *testing.T) {
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"type":"error","error":{"type":"forbidden","message":"Access to Anthropic models is not allowed from unsupported countries, regions, or territories."}}`)
	}))
	acc := addAccount(t, st, "g1")

	w := postJSON(t, g, "/v1/messages")
	if w.Code != 503 {
		t.Fatalf("expected failover to exhaustion (503), got %d", w.Code)
	}
	after, _ := st.Get(acc.ID)
	if after.Status == "error" {
		t.Fatal("geo-blocked 403 must not permanently disable the account")
	}
	if after.RateLimitedUntil == nil || time.Until(*after.RateLimitedUntil) <= 0 {
		t.Fatalf("geo-blocked 403 should cool the account down: %+v", after.RateLimitedUntil)
	}
}

func TestBanned403DisablesAccount(t *testing.T) {
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"error":{"message":"Your access has been disabled for a suspected violation of our Usage Policy."}}`)
	}))
	acc := addAccount(t, st, "b1")

	postJSON(t, g, "/v1/messages")
	after, _ := st.Get(acc.ID)
	if after.Status != "error" {
		t.Fatalf("policy-violation 403 must disable, got status %q", after.Status)
	}
}

func TestBillingExhaustedFailsOver(t *testing.T) {
	calls := 0
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(402)
			fmt.Fprint(w, `{"error":{"message":"Your credit balance is too low. Manage your billing here."}}`)
			return
		}
		fmt.Fprint(w, `{"id":"msg_ok","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	addAccount(t, st, "bill1")
	addAccount(t, st, "bill2")

	w := postJSON(t, g, "/v1/messages")
	if w.Code != 200 {
		t.Fatalf("billing failure should fail over, got %d %s", w.Code, w.Body.String())
	}
	// whichever account ate the 402 must be long-cooled, none disabled.
	cooled, disabled := 0, 0
	for _, a := range st.Snapshot() {
		if a.Status == "error" {
			disabled++
		}
		if a.RateLimitedUntil != nil && time.Until(*a.RateLimitedUntil) > time.Hour {
			cooled++
		}
	}
	if disabled != 0 {
		t.Fatal("billing exhaustion must not permanently disable")
	}
	if cooled != 1 {
		t.Fatalf("expected exactly 1 long-cooled account, got %d", cooled)
	}
}
