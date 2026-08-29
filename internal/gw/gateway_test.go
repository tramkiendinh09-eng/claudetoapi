package gw

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"claudetoapi/internal/config"
	"claudetoapi/internal/store"
)

func TestMain(m *testing.M) {
	headerlessRetryWait = 0
	os.Exit(m.Run())
}

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

func TestThinkingSignatureRetryStripsBlocks(t *testing.T) {
	calls := 0
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		raw, _ := io.ReadAll(r.Body)
		hasThinking := strings.Contains(string(raw), `"type":"thinking"`)
		if calls == 1 {
			if !hasThinking {
				t.Fatal("first attempt must keep thinking blocks")
			}
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"type":"error","error":{"type":"invalid_request_error","message":"messages.3.content.25: Invalid `+"`signature`"+` in `+"`thinking`"+` block"}}`)
			return
		}
		if hasThinking {
			t.Fatal("retry must strip thinking blocks")
		}
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	addAccount(t, st, "a1")

	body := `{"model":"claude-opus-5","max_tokens":64,"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":[{"type":"thinking","thinking":"plan","signature":"deadbeef"},{"type":"text","text":"done"}]},{"role":"user","content":"next"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("anthropic-beta", "claude-code-20250219,thinking-display-updates-2026-08-18,task-budgets-2026-03-13")
	w := httptest.NewRecorder()
	g.handleMessages(w, req, false)
	if w.Code != 200 {
		t.Fatalf("retry should succeed: %d %s", w.Code, w.Body.String())
	}
	if calls != 2 {
		t.Fatalf("expected 2 upstream calls, got %d", calls)
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

func TestWindowsFromHeaders(t *testing.T) {
	h := http.Header{}
	now := time.Now()
	// absent headers -> nil
	if w5, w7 := WindowsFromHeaders(h, now); w5 != nil || w7 != nil {
		t.Fatal("empty headers must yield nil windows")
	}
	// full headers -> both parsed
	h.Set("anthropic-ratelimit-unified-5h-utilization", "0.42")
	h.Set("anthropic-ratelimit-unified-5h-reset", strconv.FormatInt(now.Add(3*time.Hour).Unix(), 10))
	h.Set("anthropic-ratelimit-unified-7d-utilization", "1.5") // clamped to 1
	h.Set("anthropic-ratelimit-unified-7d-reset", strconv.FormatInt(now.Add(5*24*time.Hour).Unix(), 10))
	w5, w7 := WindowsFromHeaders(h, now)
	if w5 == nil || w7 == nil {
		t.Fatalf("windows not parsed: %+v %+v", w5, w7)
	}
	if w5.Utilization != 0.42 {
		t.Fatalf("5h utilization = %v", w5.Utilization)
	}
	if w7.Utilization != 1.0 {
		t.Fatalf("7d utilization should clamp to 1, got %v", w7.Utilization)
	}
	// expired reset -> window dropped (stale)
	h.Set("anthropic-ratelimit-unified-5h-reset", strconv.FormatInt(now.Add(-time.Hour).Unix(), 10))
	if w5, _ := WindowsFromHeaders(h, now); w5 != nil {
		t.Fatal("expired 5h window must be nil")
	}
}

func TestSuccessHarvestsRateWindows(t *testing.T) {
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reset := strconv.FormatInt(time.Now().Add(4*time.Hour).Unix(), 10)
		w.Header().Set("anthropic-ratelimit-unified-5h-utilization", "0.55")
		w.Header().Set("anthropic-ratelimit-unified-5h-reset", reset)
		w.Header().Set("anthropic-ratelimit-unified-7d-utilization", "0.18")
		w.Header().Set("anthropic-ratelimit-unified-7d-reset", strconv.FormatInt(time.Now().Add(6*24*time.Hour).Unix(), 10))
		fmt.Fprint(w, `{"id":"msg_w","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":3,"output_tokens":2}}`)
	}))
	acc := addAccount(t, st, "w1")

	w := postJSON(t, g, "/v1/messages")
	if w.Code != 200 {
		t.Fatalf("forward failed: %d", w.Code)
	}
	after, _ := st.Get(acc.ID)
	if after.RateWindow5h == nil || after.RateWindow5h.Utilization != 0.55 {
		t.Fatalf("5h window not harvested: %+v", after.RateWindow5h)
	}
	if after.RateWindow7d == nil || after.RateWindow7d.Utilization != 0.18 {
		t.Fatalf("7d window not harvested: %+v", after.RateWindow7d)
	}
}

func TestRefreshEndpointParsesAccountID(t *testing.T) {
	// /admin/accounts/{id}/refresh: pathID must read the pattern value, not
	// the trailing segment ("refresh"), or every refresh returns 400.
	req := httptest.NewRequest(http.MethodPost, "/admin/accounts/1/refresh", nil)
	req.SetPathValue("id", "1")
	id, err := pathID(req)
	if err != nil {
		t.Fatalf("pathID failed on refresh path: %v", err)
	}
	if id != 1 {
		t.Fatalf("pathID = %d, want 1", id)
	}

	// DELETE/PATCH shape: pattern value still wins, id from the last segment.
	req2 := httptest.NewRequest(http.MethodDelete, "/admin/accounts/7", nil)
	req2.SetPathValue("id", "7")
	if id, err := pathID(req2); err != nil || id != 7 {
		t.Fatalf("pathID on plain id path: %d %v", id, err)
	}
}

func TestAccountStyleOverridesGlobal(t *testing.T) {
	if got := accountStyle(&store.Account{OutputStyle: "concise"}, "proactive"); got != "concise" {
		t.Fatalf("account style must win, got %q", got)
	}
	if got := accountStyle(&store.Account{}, "proactive"); got != "proactive" {
		t.Fatalf("unset account must inherit global, got %q", got)
	}
	if got := accountStyle(nil, "concise"); got != "concise" {
		t.Fatalf("nil account must inherit global, got %q", got)
	}
	if got := accountStyle(&store.Account{}, ""); got != "" {
		t.Fatalf("no styles anywhere must stay empty, got %q", got)
	}
}

func TestInvalidGrantDisablesInsteadOfCooldownLoop(t *testing.T) {
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"error": "invalid_grant", "error_description": "Refresh token not found or invalid"}`)
	}))
	acc := addAccount(t, st, "dead-rt")
	// put the account into the state a dead refresh token leaves behind
	_ = st.Update(acc.ID, func(a *store.Account) {
		a.Credentials.AccessToken = ""
		a.Credentials.RefreshToken = "expired-token"
		a.Credentials.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	})

	postJSON(t, g, "/v1/messages")
	after, _ := st.Get(acc.ID)
	if after.Status != "error" {
		t.Fatalf("invalid_grant must surface as re-authorization error, got status %q", after.Status)
	}
	if !strings.Contains(after.Error, "重新授权") {
		t.Fatalf("error must point at the reauthorize action: %q", after.Error)
	}
	if after.RateLimitedUntil != nil && time.Until(*after.RateLimitedUntil) > 0 {
		t.Fatal("invalid_grant must not cooldown-loop; the account is already in error state")
	}
}

func TestNonstreamPromotesToStreamAndAggregates(t *testing.T) {
	var gotStream bool
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotStream = strings.Contains(string(raw), `"stream":true`)
		w.Header().Set("content-type", "text/event-stream")
		fmt.Fprint(w, "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_p\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"usage\":{\"input_tokens\":3}}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n")
		fmt.Fprint(w, "data: {\"type\":\"message_stop\"}\n\n")
	}))
	addAccount(t, st, "p1")
	w := postJSON(t, g, "/v1/messages")
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if !gotStream {
		t.Fatal("non-stream client request must be promoted to stream=true upstream")
	}
	if ct := w.Header().Get("content-type"); !strings.Contains(ct, "json") {
		t.Fatalf("client still expects JSON, got %s", ct)
	}
	if !strings.Contains(w.Body.String(), `"ok"`) {
		t.Fatalf("aggregated text missing: %s", w.Body.String())
	}
	rec := g.ledger.recordsFor(0, 10)[0]
	if rec.Input != 3 || rec.Output != 1 {
		t.Fatalf("ledger %+v", rec)
	}
}

func TestSingleAccount429Passthrough(t *testing.T) {
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		fmt.Fprint(w, `{"type":"error","error":{"type":"rate_limit_error","message":"rpm"}}`)
	}))
	addAccount(t, st, "only")
	w := postJSON(t, g, "/v1/messages")
	if w.Code != 429 {
		t.Fatalf("want 429 passthrough, got %d %s", w.Code, w.Body.String())
	}
	if ra := w.Header().Get("Retry-After"); ra == "" {
		t.Fatal("missing Retry-After")
	} else if n := parseInt(ra); n < 30 || n > 31 {
		t.Fatalf("Retry-After = %s, want ~30s fallback", ra)
	}
	if !strings.Contains(w.Body.String(), "rate_limit_error") {
		t.Fatalf("body: %s", w.Body.String())
	}
	for _, a := range st.Snapshot() {
		if a.RateLimitedUntil != nil && time.Until(*a.RateLimitedUntil) > 0 {
			t.Fatalf("headerless 429 must not freeze the account store: %+v", a.RateLimitedUntil)
		}
	}
}

func TestHeaderless429RetriesThenSucceeds(t *testing.T) {
	calls := 0
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= headerlessRetryMax {
			w.WriteHeader(429)
			fmt.Fprint(w, `{"type":"error","error":{"type":"rate_limit_error"}}`)
			return
		}
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"id":"msg_ok","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	addAccount(t, st, "retry")
	w := postJSON(t, g, "/v1/messages")
	if w.Code != 200 {
		t.Fatalf("want 200 after in-request retry, got %d %s", w.Code, w.Body.String())
	}
	if calls != headerlessRetryMax+1 {
		t.Fatalf("calls=%d want %d", calls, headerlessRetryMax+1)
	}
	if !strings.Contains(w.Body.String(), `"ok"`) {
		t.Fatalf("body %s", w.Body.String())
	}
}

func TestHeaderless429DoesNotFreezeCC(t *testing.T) {
	calls := 0
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= headerlessRetryMax+1 {
			w.WriteHeader(429)
			fmt.Fprint(w, `{"type":"error","error":{"type":"rate_limit_error"}}`)
			return
		}
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"id":"msg_cc","content":[{"type":"text","text":"ok"}],"usage":{"input_tokens":1,"output_tokens":1}}`)
	}))
	acc := addAccount(t, st, "mix")
	if w := postJSON(t, g, "/v1/messages"); w.Code != 429 {
		t.Fatalf("non-cc want 429, got %d", w.Code)
	}
	after, _ := st.Get(acc.ID)
	if after.RateLimitedUntil != nil && time.Until(*after.RateLimitedUntil) > 0 {
		t.Fatal("headerless 429 must not freeze the account")
	}
	body := `{"model":"claude-sonnet-4-5-20250929","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hi"}],"metadata":{"user_id":"{\"device_id\":\"x\"}"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("User-Agent", "claude-cli/2.1.247 (external, cli)")
	w2 := httptest.NewRecorder()
	g.handleMessages(w2, req, false)
	if w2.Code != 200 {
		t.Fatalf("cc stream after headerless 429 want 200, got %d %s", w2.Code, w2.Body.String())
	}
	if calls != headerlessRetryMax+2 {
		t.Fatalf("cc stream must still hit upstream, calls=%d", calls)
	}
}

func TestCountTokensStripsMaxTokens(t *testing.T) {
	var gotBody string
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		gotBody = string(raw)
		fmt.Fprint(w, `{"input_tokens":99}`)
	}))
	addAccount(t, st, "c1")
	w := postJSON(t, g, "/v1/messages/count_tokens")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if strings.Contains(gotBody, "max_tokens") || strings.Contains(gotBody, `"stream"`) {
		t.Fatalf("count_tokens leaked extras: %s", gotBody)
	}
}

func TestCountTokens429DoesNotCooldown(t *testing.T) {
	g, _, st := newTestGateway(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		fmt.Fprint(w, `{"type":"error","error":{"type":"rate_limit_error"}}`)
	}))
	acc := addAccount(t, st, "ct")
	w := postJSON(t, g, "/v1/messages/count_tokens")
	if w.Code != 429 {
		t.Fatalf("want 429, got %d %s", w.Code, w.Body.String())
	}
	after, _ := st.Get(acc.ID)
	if after.RateLimitedUntil != nil && time.Until(*after.RateLimitedUntil) > 0 {
		t.Fatalf("count_tokens 429 must not freeze generation: %+v", after.RateLimitedUntil)
	}
}
