package gw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"claudetoapi/internal/config"
	"claudetoapi/internal/mimicry"
	"claudetoapi/internal/oauth"
	"claudetoapi/internal/profile"
	"claudetoapi/internal/store"
)

const defaultUpstreamBase = "https://api.anthropic.com"

// headerlessRetryWait is the pause between in-request retries of a
// headerless 429. Tests set it to 0.
var headerlessRetryWait = 8 * time.Second

const headerlessRetryMax = 2

// Gateway is the forwarding core.
type Gateway struct {
	cfg       *config.Config
	st        *store.Store
	chain     *Chain
	telemetry *TelemetryManager
	// upstreamBase is overridable so integration tests can point the whole
	// forwarding pipeline at a fake upstream.
	upstreamBase string

	// tokenMu serializes refresh per account (keyed by account ID so one
	// slow refresh never blocks another account's traffic).
	tokenMu   sync.Mutex
	tokenLock map[int64]*sync.Mutex
	// slots enforces per-account concurrency caps.
	slots sync.Map

	// headerlessUntil is an in-memory backoff for Anthropic 429s that
	// carry no reset headers. Those are a non-stream / third-party lane,
	// not the 5h/7d quota: freezing the account store would also block
	// working Claude Code stream=true traffic on the same OAuth token.
	headerlessMu    sync.Mutex
	headerlessUntil map[int64]time.Time

	// ledger records per-account usage: today/total aggregates plus a
	// per-request log with separate prompt-cache write/read counters.
	ledger *usageLedger
}

func New(cfg *config.Config, st *store.Store) *Gateway {
	g := &Gateway{
		cfg:          cfg,
		st:           st,
		chain:        NewChain(),
		telemetry:    nil,
		upstreamBase: defaultUpstreamBase,
	}
	g.ledger = newUsageLedger(filepath.Join(cfg.AccountsDir, "usage_history.json"))
	g.ledger.startSaver()
	g.tokenLock = map[int64]*sync.Mutex{}
	g.headerlessUntil = map[int64]time.Time{}
	return g
}

func (g *Gateway) noteHeaderless(id int64, d time.Duration) {
	if d <= 0 {
		d = fallback429Cooldown
	}
	until := time.Now().Add(d)
	g.headerlessMu.Lock()
	g.headerlessUntil[id] = until
	g.headerlessMu.Unlock()
	slog.Warn("headerless_429_lane", "account_id", id, "until", until.Format(time.RFC3339))
}

func (g *Gateway) headerlessActive(id int64) (time.Time, bool) {
	g.headerlessMu.Lock()
	defer g.headerlessMu.Unlock()
	until, ok := g.headerlessUntil[id]
	if !ok || !time.Now().Before(until) {
		return time.Time{}, false
	}
	return until, true
}

// lockAccount takes the per-account token mutex.
func (g *Gateway) lockAccount(id int64) *sync.Mutex {
	g.tokenMu.Lock()
	defer g.tokenMu.Unlock()
	mu, ok := g.tokenLock[id]
	if !ok {
		mu = &sync.Mutex{}
		g.tokenLock[id] = mu
	}
	return mu
}

// CloseUsage stops the ledger saver after a final flush.
func (g *Gateway) CloseUsage() { g.ledger.close() }

// UsageAggregates returns per-account today/total counters (admin endpoint).
func (g *Gateway) UsageAggregates() map[int64]UsageAgg { return g.ledger.aggregates() }

// UsageRecords returns the newest request records, optionally filtered by account.
func (g *Gateway) UsageRecords(accountID int64, limit int) []UsageRecord {
	return g.ledger.recordsFor(accountID, limit)
}

// Telemetry returns the telemetry manager (lazily wired by main).
func (g *Gateway) Telemetry() *TelemetryManager { return g.telemetry }

// SetTelemetry wires the telemetry manager.
func (g *Gateway) SetTelemetry(m *TelemetryManager) { g.telemetry = m }

// acquireSlot enforces the per-account concurrency cap (default 2).
func (g *Gateway) acquireSlot(acc *store.Account) bool {
	limit := acc.Concurrency
	if limit <= 0 {
		limit = 2
	}
	v, _ := g.slots.LoadOrStore(acc.ID, make(chan struct{}, limit))
	ch := v.(chan struct{})
	select {
	case ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (g *Gateway) releaseSlot(acc *store.Account) {
	if v, ok := g.slots.Load(acc.ID); ok {
		ch := v.(chan struct{})
		select {
		case <-ch:
		default:
		}
	}
}

// ---- token management ----

// accessToken returns a valid token, refreshing when near expiry. A failed
// refresh without a refresh_token disables the account.
func (g *Gateway) accessToken(ctx context.Context, acc *store.Account) (string, error) {
	mu := g.lockAccount(acc.ID)
	mu.Lock()
	defer mu.Unlock()

	if acc.Credentials.AccessToken != "" {
		if exp, err := time.Parse(time.RFC3339, acc.Credentials.ExpiresAt); err == nil {
			if time.Until(exp) > 3*time.Minute {
				return acc.Credentials.AccessToken, nil
			}
		} else {
			return acc.Credentials.AccessToken, nil // unknown expiry: trust until 401
		}
	}
	if acc.Credentials.RefreshToken == "" {
		g.setError(acc.ID, "token expired and no refresh_token available")
		return "", fmt.Errorf("account %d: no refresh_token", acc.ID)
	}
	proxy := g.geoFor(acc).ProxyURL
	oc := oauth.New(proxy)
	tr, err := oc.Refresh(ctx, acc.Credentials.RefreshToken)
	if err != nil {
		// invalid_grant means the refresh token family is dead (rotated by
		// another client holding the same credentials, or revoked). Retrying
		// can never succeed — surface a re-authorization error immediately
		// instead of endless cooldown loops.
		if strings.Contains(err.Error(), "invalid_grant") {
			g.setError(acc.ID, "需要重新授权: refresh token 已失效(invalid_grant)——同一凭据可能在其他客户端刷新轮换或会话被吊销,请在控制台对该账号执行「重新授权」")
			return "", fmt.Errorf("account %d refresh: %w", acc.ID, err)
		}
		// Other failures are usually transient; cool the account down
		// rather than hard-disabling on the first strike.
		g.cooldown(acc.ID, 10*time.Minute, "oauth_refresh_failed: "+err.Error())
		return "", fmt.Errorf("account %d refresh: %w", acc.ID, err)
	}
	slog.Info("token_refreshed", "account_id", acc.ID, "account", acc.Name,
		"rotated_rt", tr.RefreshToken != "")
	newAcc, _ := g.st.Get(acc.ID)
	_ = g.st.Update(acc.ID, func(a *store.Account) {
		a.Credentials.AccessToken = tr.AccessToken
		if tr.RefreshToken != "" {
			a.Credentials.RefreshToken = tr.RefreshToken
		}
		if tr.ExpiresIn > 0 {
			a.Credentials.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
		} else {
			a.Credentials.ExpiresAt = time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339)
		}
		if tr.Account != nil {
			if a.Extra.AccountUUID == "" && tr.Account.UUID != "" {
				a.Extra.AccountUUID = tr.Account.UUID
			}
			if a.Extra.Email == "" {
				a.Extra.Email = tr.Account.EmailAddress
			}
		}
	})
	_ = newAcc
	return tr.AccessToken, nil
}

func (g *Gateway) setError(id int64, msg string) {
	_ = g.st.Update(id, func(a *store.Account) { a.Status = "error"; a.Error = msg })
	slog.Warn("account_disabled", "account_id", id, "reason", msg)
}

func (g *Gateway) cooldown(id int64, d time.Duration, reason string) {
	until := time.Now().Add(d)
	_ = g.st.Update(id, func(a *store.Account) {
		a.Status = "active"
		a.RateLimitedUntil = &until
		a.RateLimitReason = reason
	})
	slog.Warn("account_cooldown", "account_id", id, "until", until.Format(time.RFC3339), "reason", reason)
}

// geoIdentity is the resolved egress identity for one account: proxy URL
// plus the timezone / locale that must stay consistent with it.
type geoIdentity struct {
	ProxyURL string
	Timezone *time.Location
	Language string
	ProxyName string
}

var defaultGeo = geoIdentity{Language: "en-US,en;q=0.9"}

// resolveProxy maps a spec (named pool entry or raw URL) to its egress
// identity. Unknown names fall back to treating the spec as a raw URL.
func (g *Gateway) resolveProxy(spec string) geoIdentity {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return defaultGeo
	}
	for _, p := range g.cfg.Proxies {
		if p.Name == spec {
			geo := geoIdentity{ProxyURL: p.URL, Language: "en-US,en;q=0.9", ProxyName: p.Name}
			if p.Timezone != "" {
				if loc, err := time.LoadLocation(p.Timezone); err == nil {
					geo.Timezone = loc
				}
			}
			if p.Language != "" {
				geo.Language = p.Language
			}
			return geo
		}
	}
	if strings.Contains(spec, "://") {
		return geoIdentity{ProxyURL: spec, Language: defaultGeo.Language}
	}
	return defaultGeo
}

// accountStyle resolves the output style for one account: the account's own
// choice wins; unset accounts inherit the global default.
func accountStyle(acc *store.Account, global string) string {
	if acc != nil && acc.OutputStyle != "" {
		return acc.OutputStyle
	}
	return global
}

// geoFor returns the effective egress identity for an account.
func (g *Gateway) geoFor(acc *store.Account) geoIdentity {
	switch {
	case acc.Proxy != "":
		return g.resolveProxy(acc.Proxy)
	case acc.ProxyURL != "":
		return g.resolveProxy(acc.ProxyURL)
	default:
		return g.resolveProxy(g.cfg.DefaultProxyURL)
	}
}

// ---- account selection ----

var errNoAccounts = errors.New("no available accounts")

// pick chooses an account: session sticky first, then an account whose
// frozen CLI version matches the inbound UA (so a 2.1.226 client does not
// land on a 2.1.247 token), then least-recently-used active.
func (g *Gateway) pick(sessionHash string, exclude map[int64]bool, inboundUA string) *store.Account {
	now := time.Now()
	if id, ok := g.chain.Sticky(sessionHash); ok && !exclude[id] {
		if acc, err := g.st.Get(id); err == nil && acc.Active(now) {
			return acc
		}
	}
	want, wantOK := versionTriple(inboundUA)
	var best, matched *store.Account
	for _, acc := range g.st.Snapshot() {
		if exclude[acc.ID] || !acc.Active(now) {
			continue
		}
		if wantOK && acc.Fingerprint != nil {
			if got, ok := versionTriple(acc.Fingerprint.UserAgent); ok && got == want {
				if olderUsed(acc, matched) {
					matched = acc
				}
			}
		}
		if olderUsed(acc, best) {
			best = acc
		}
	}
	if matched != nil {
		return matched
	}
	return best
}

func olderUsed(acc, best *store.Account) bool {
	if acc == nil {
		return false
	}
	if best == nil {
		return true
	}
	at, bt := acc.LastUsedAt, best.LastUsedAt
	return at == nil || (bt != nil && at.Before(*bt))
}

// ---- fingerprint resolution ----

// resolveFingerprint returns the per-account identity, creating it lazily.
// Inbound client UAs are never adopted onto a pool OAuth account — the same
// token presenting 2.1.246 Windows passthrough and 2.1.241 Linux/arm64 mimic
// is what got an account banned. CLI version may ride a one-way upgrade to
// the configured profile (like a real user updating claude); OS/arch/runtime
// stay sticky.
func (g *Gateway) resolveFingerprint(acc *store.Account, clientUA string) (fp *store.Fingerprint, prof *profile.Profile) {
	target := profile.Lookup(g.cfg.ProfileName)
	if acc.Fingerprint != nil && acc.Fingerprint.ClientID != "" {
		fp = acc.Fingerprint
		if inbound := strings.TrimSpace(clientUA); inbound != "" && inbound != orDefault(fp.UserAgent, target.UserAgent) {
			slog.Debug("identity_unify_ignore_inbound_ua",
				"account_id", acc.ID,
				"inbound", shortUA(inbound),
				"sticky", shortUA(orDefault(fp.UserAgent, target.UserAgent)))
		}
		upgraded := upgradeFingerprint(fp, target)
		missingPlatform := fp.OS == "" || fp.Arch == "" || fp.Runtime == "" || fp.RuntimeVersion == "" || fp.Terminal == "" || fp.Shell == ""
		if upgraded != nil {
			fp.UserAgent = upgraded.UserAgent
			fp.SDKVersion = upgraded.SDKVersion
			fp.Profile = upgraded.Profile
			fp.UpdatedAt = upgraded.UpdatedAt
		}
		prof = profileFromFingerprint(fp, target)
		applyMachinePersona(fp)
		seedStickyPlatform(fp, prof)
		if upgraded != nil || missingPlatform {
			snap := *fp
			_ = g.st.Update(acc.ID, func(a *store.Account) {
				if a.Fingerprint == nil {
					return
				}
				a.Fingerprint.UserAgent = snap.UserAgent
				a.Fingerprint.SDKVersion = snap.SDKVersion
				a.Fingerprint.Profile = snap.Profile
				a.Fingerprint.OS = snap.OS
				a.Fingerprint.Arch = snap.Arch
				a.Fingerprint.Runtime = snap.Runtime
				a.Fingerprint.RuntimeVersion = snap.RuntimeVersion
				a.Fingerprint.Terminal = snap.Terminal
				a.Fingerprint.Shell = snap.Shell
				a.Fingerprint.UpdatedAt = snap.UpdatedAt
			})
		}
		return fp, prof
	}

	prof = profile.Lookup(g.cfg.ProfileName)
	entry := g.cfg.Mimicry.DefaultEntrypoint
	if entry == "" {
		entry = "cli"
	}
	newFP := newStickyFingerprint(prof, entry)
	_ = g.st.Update(acc.ID, func(a *store.Account) { a.Fingerprint = newFP })
	return newFP, prof
}

// profileFromFingerprint rebuilds the Profile view from the frozen account
// identity. Unknown stored profile names fall back to cfg Default for
// stainless defaults, then overlay UA / SDK / CLI version from the fingerprint
// so billing and betas never disagree with the sticky User-Agent.
func profileFromFingerprint(fp *store.Fingerprint, fallback *profile.Profile) *profile.Profile {
	if fallback == nil {
		fallback = profile.Default
	}
	base := fallback
	if fp != nil && fp.Profile != "" {
		if p, ok := profile.Registry[fp.Profile]; ok {
			base = p
		}
	}
	out := *base
	if fp == nil {
		return &out
	}
	if fp.UserAgent != "" {
		out.UserAgent = fp.UserAgent
	}
	if fp.SDKVersion != "" {
		out.SDKVersion = fp.SDKVersion
	}
	if v, ok := cliVersionFromUA(out.UserAgent); ok {
		out.CLIVersion = v
	}
	return &out
}

func newStickyFingerprint(prof *profile.Profile, entrypoint string) *store.Fingerprint {
	fp := &store.Fingerprint{
		ClientID:   newClientID(),
		Entrypoint: entrypoint,
		Profile:    prof.Name,
		UserAgent:  prof.UserAgent,
		SDKVersion: prof.SDKVersion,
		UpdatedAt:  time.Now().Unix(),
	}
	applyMachinePersona(fp)
	seedStickyPlatform(fp, prof)
	return fp
}

func seedStickyPlatform(fp *store.Fingerprint, prof *profile.Profile) {
	if fp == nil || prof == nil {
		return
	}
	if fp.OS == "" {
		fp.OS = prof.Stainless["X-Stainless-OS"]
	}
	if fp.Arch == "" {
		fp.Arch = prof.Stainless["X-Stainless-Arch"]
	}
	if fp.Runtime == "" {
		fp.Runtime = prof.Stainless["X-Stainless-Runtime"]
	}
	if fp.RuntimeVersion == "" {
		fp.RuntimeVersion = prof.Stainless["X-Stainless-Runtime-Version"]
	}
}

// upgradeFingerprint returns a copy of version fields when the configured
// profile is newer than the stored UA. OS/arch/runtime are left alone.
func upgradeFingerprint(fp *store.Fingerprint, prof *profile.Profile) *store.Fingerprint {
	if fp == nil || prof == nil {
		return nil
	}
	current := orDefault(fp.UserAgent, "")
	if current == "" || newerVersion(prof.UserAgent, current) {
		out := *fp
		out.UserAgent = prof.UserAgent
		out.SDKVersion = prof.SDKVersion
		out.Profile = prof.Name
		out.UpdatedAt = time.Now().Unix()
		return &out
	}
	return nil
}

// provisionFingerprint creates the persistent identity for a new account
// with the requested entrypoint persona.
func (g *Gateway) provisionFingerprint(acc *store.Account, entrypoint string) *store.Fingerprint {
	if acc.Fingerprint != nil && acc.Fingerprint.ClientID != "" {
		return acc.Fingerprint
	}
	prof := profile.Lookup(g.cfg.ProfileName)
	if entrypoint == "" {
		entrypoint = g.cfg.Mimicry.DefaultEntrypoint
	}
	fp := newStickyFingerprint(prof, entrypoint)
	acc.Fingerprint = fp
	return fp
}

func newClientID() string {
	b := make([]byte, 32)
	_, _ = readRand(b)
	return hexEncode(b)
}

// HandleModels serves the model list the CLI advertises (subset of
// profile.DefaultModels filtered by configured accounts).
func (g *Gateway) HandleModels(w http.ResponseWriter, r *http.Request) {
	type model struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		DisplayName string `json:"display_name"`
	}
	models := []model{}
	for _, m := range profile.DefaultModels {
		models = append(models, model{ID: m.ID, Type: m.Type, DisplayName: m.DisplayName})
	}
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data":    models,
		"has_more": false,
	})
}

// RefreshExpiring rotates tokens for accounts whose access tokens expire
// soon (called by the background loop).
func (g *Gateway) RefreshExpiring() {
	for _, acc := range g.st.Snapshot() {
		if acc.Status != "active" || acc.Credentials.RefreshToken == "" {
			continue
		}
		exp, err := time.Parse(time.RFC3339, acc.Credentials.ExpiresAt)
		if err != nil || time.Until(exp) > 3*time.Minute {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if _, err := g.accessToken(ctx, acc); err != nil {
			slog.Warn("background_refresh_failed", "account_id", acc.ID, "error", err.Error())
		}
		cancel()
	}
}

// ---- request handling ----

// HandleMessages is the /v1/messages entry point.
func (g *Gateway) HandleMessages(w http.ResponseWriter, r *http.Request) {
	g.handleMessages(w, r, false)
}

// HandleCountTokens is the /v1/messages/count_tokens entry point: the same
// selection/mimicry pipeline but forwarded to the count_tokens endpoint so a
// token-count request never consumes a real generation.
func (g *Gateway) HandleCountTokens(w http.ResponseWriter, r *http.Request) {
	g.handleMessages(w, r, true)
}

func (g *Gateway) handleMessages(w http.ResponseWriter, r *http.Request, countTokens bool) {
	body, _, err := mimicry.ReadJSONBody(r, int64(g.cfg.MaxBodyMB)<<20)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request_error", "request body is not valid JSON: "+err.Error())
		return
	}

	clientUA := r.Header.Get("User-Agent")
	isCC := mimicry.IsClaudeCodeClient(clientUA, body)
	stream, _ := body["stream"].(bool)
	model, _ := body["model"].(string)

	// Watermark normalization (runs for both real-CC and mimic traffic).
	if !g.cfg.Mimicry.DisableDatelineNormalization {
		mimicry.NormalizeDateline(body)
	}

	sessionHash := SessionHash(body)

	exclude := map[int64]bool{}
	attempts := g.cfg.Mimicry.MaxAttempts
	var lastRL *rateLimitEcho
	for i := 0; i < attempts; i++ {
		acc := g.pick(sessionHash, exclude, clientUA)
		if acc == nil {
			g.writeGiveUp(w, lastRL)
			return
		}
		done, rl := g.forwardOnce(w, r, acc, body, forwardOpts{
			IsCC: isCC, Stream: stream, Model: model, SessionHash: sessionHash, ClientHeaders: r.Header,
			CountTokens: countTokens,
		})
		if done {
			return
		}
		if rl != nil {
			lastRL = rl
		}
		exclude[acc.ID] = true
	}
	g.writeGiveUp(w, lastRL)
}

// writeGiveUp is the no-account terminal: if the last attempt was a 429,
// pass that 429 through (so clients back off) instead of translating it
// into a 503 overloaded_error that they retry immediately.
func (g *Gateway) writeGiveUp(w http.ResponseWriter, rl *rateLimitEcho) {
	if rl != nil {
		g.writeRateLimited(w, rl)
		return
	}
	g.writeOverloaded(w)
}

type rateLimitEcho struct {
	Decision RateLimitDecision
	Body     string
}

func (g *Gateway) writeRateLimited(w http.ResponseWriter, rl *rateLimitEcho) {
	secs := int64(rl.Decision.Cooldown.Seconds()) + 1
	if secs < 1 {
		secs = 1
	}
	if secs > 3600 {
		secs = 3600
	}
	w.Header().Set("retry-after", strconv.FormatInt(secs, 10))
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	body := strings.TrimSpace(rl.Body)
	if body == "" {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "error",
			"error": map[string]any{
				"type":    "rate_limit_error",
				"message": "rate limited by upstream",
			},
		})
		return
	}
	_, _ = io.WriteString(w, body)
}

// writeOverloaded reports upstream exhaustion with a Retry-After derived from
// the accounts' rate-limit windows so well-behaved clients back off exactly
// as long as needed.
func (g *Gateway) writeOverloaded(w http.ResponseWriter) {
	if secs := g.retryAfterSeconds(); secs > 0 {
		w.Header().Set("retry-after", strconv.FormatInt(secs, 10))
	}
	writeErr(w, http.StatusServiceUnavailable, "overloaded_error", "no available upstream accounts")
}

// retryAfterSeconds returns seconds until the earliest active account leaves
// its rate-limit window (0 when no window is known).
func (g *Gateway) retryAfterSeconds() int64 {
	var best int64
	for _, acc := range g.st.Snapshot() {
		if acc.Status != "active" || acc.RateLimitedUntil == nil {
			continue
		}
		secs := int64(time.Until(*acc.RateLimitedUntil).Seconds()) + 1
		if secs > 0 && (best == 0 || secs < best) {
			best = secs
		}
	}
	if best > 3600 {
		best = 3600
	}
	return best
}

type forwardOpts struct {
	IsCC          bool
	Stream        bool
	Model         string
	SessionHash   string
	ClientHeaders http.Header
	CountTokens   bool
}

// forwardOnce sends the request through one account. done=true means the
// response has been fully handled (success or terminal error). A non-nil
// rateLimitEcho on done=false lets the caller pass a 429 through when this
// was the last account.
func (g *Gateway) forwardOnce(w http.ResponseWriter, r *http.Request, acc *store.Account, body map[string]any, opts forwardOpts) (done bool, rl *rateLimitEcho) {
	ctx := r.Context()
	start := time.Now()

	// Auto-mode security monitor: opus + max_tokens=64 + 450KB transcript
	// is a dedicated OAuth 429 class. Returning 429 fail-closes every
	// tool call in VS Code. Default of the classifier is ALLOW.
	if !opts.CountTokens && isAutoModeClassifier(body) {
		writeAutoModeAllow(w, opts.Model)
		g.recordAttempt(acc, opts, http.StatusOK, start, usageAcc{output: 5})
		slog.Info("automode_classifier_allow", "account_id", acc.ID, "model", opts.Model, "ua", shortUA(opts.ClientHeaders.Get("User-Agent")))
		return true, nil
	}

	// Non-stream headerless 429s are a VS Code / agent-sdk lane. Do not
	// bounce 429 at the client (that is the 20s retry storm). Wait out
	// the in-memory gate, then send.
	if !opts.Stream || opts.CountTokens {
		if until, ok := g.headerlessActive(acc.ID); ok {
			d := time.Until(until)
			if d > 0 && headerlessRetryWait > 0 {
				slog.Info("headerless_wait", "account_id", acc.ID, "wait_s", int(d.Seconds())+1)
				timer := time.NewTimer(d)
				select {
				case <-ctx.Done():
					timer.Stop()
					return true, nil
				case <-timer.C:
				}
			}
		}
	}

	if !g.acquireSlot(acc) {
		return false, nil
	}
	heldSlot := true
	defer func() {
		if heldSlot {
			g.releaseSlot(acc)
		}
	}()

	token, err := g.accessToken(ctx, acc)
	if err != nil {
		return false, nil // account unusable now; fail over
	}

	geo := g.geoFor(acc)
	// Align the dateline date with the exit IP's calendar day: the CLI stamps
	// its local date into the prompt, so a US egress must carry the US date.
	if geo.Timezone != nil {
		mimicry.ShiftDatelines(body, time.Now().In(geo.Timezone).Format("2006-01-02"))
	}

	fp, prof := g.resolveFingerprint(acc, opts.ClientHeaders.Get("User-Agent"))

	// Telemetry bypass: lazily start the account's background runner
	// (flag-eval pulls + first-party events) on its egress path. Fingerprint
	// is resolved first so a CLI version upgrade is visible to the runner.
	if g.telemetry != nil {
		g.telemetry.EnsureStarted(acc, token)
	}
	persona := mimicry.PersonaFor(fp.Entrypoint)
	// chain.Next advances the conversation chain: promptID stays stable,
	// prevReqID links to the previous request (first request: empty).
	promptID, prevReqID, _ := g.chain.Next(opts.SessionHash)
	isNewConversation := prevReqID == ""

	if !opts.IsCC {
		attribution := mimicry.BuildAttribution(mimicry.AttributionOptions{
			CLIVersion:  prof.CLIVersion,
			Fingerprint: mimicry.ComputeVersionFingerprint(mimicry.FirstUserText(body), prof.CLIVersion),
			Entrypoint:  persona.Entrypoint,
			PrevReqID:   prevReqID,
			PromptID:    promptID,
		})
		// Session id: native UUID when the client carries one, otherwise a
		// UUID deterministically derived from the conversation hash so it
		// stays stable across turns (real CLI sessions are process-stable).
		sessionID := sessionUUID(opts.SessionHash)
		if sessionID == "" {
			sessionID = mimicry.UUIDFromSeed("claudetoapi:" + opts.SessionHash)
		}
		mimicry.Transform(body, mimicry.TransformOptions{
			Profile: mimicry.ProfileView{
				CLIVersion:       prof.CLIVersion,
				DefaultMaxTokens: prof.DefaultMaxTokens,
				MaxTokensUpper:   prof.MaxTokensUpper,
			},
			Persona:     persona,
			Attribution: attribution,
			ClientID:    fp.ClientID,
			AccountUUID: acc.Extra.AccountUUID,
			SessionID:   sessionID,
			CacheTTL1h:  cacheTTLIs1h(body),
			OutputStyle: accountStyle(acc, g.cfg.Mimicry.OutputStyle),
			CountTokens: opts.CountTokens,
		})
	} else {
		// Real CLI: sticky identity is complete (UA + billing + betas).
		// Signed thinking is bound to that surface — if inbound CLI version
		// or billing disagrees, strip thinking before the first hop so
		// Anthropic never 400s and the token never presents two releases.
		stickyUA := orDefault(fp.UserAgent, prof.UserAgent)
		inUA := opts.ClientHeaders.Get("User-Agent")
		bodyVer, _, bodyVerOK := mimicry.BillingCLIVersion(body)
		bodyEP := mimicry.BillingEntrypoint(body)
		signedThinking := mimicry.HasSignedThinking(body)
		identityMismatch := false
		if signedThinking {
			if cliVersionMismatch(inUA, stickyUA) {
				identityMismatch = true
			}
			if bodyVerOK && bodyVer != prof.CLIVersion {
				identityMismatch = true
			}
			if bodyEP != "" && fp.Entrypoint != "" && bodyEP != fp.Entrypoint {
				identityMismatch = true
			}
		}
		if identityMismatch {
			if mimicry.StripThinkingBlocks(body) {
				slog.Warn("thinking_strip_identity_mismatch",
					"account_id", acc.ID,
					"inbound", shortUA(inUA),
					"sticky", shortUA(stickyUA),
					"body_cc", bodyVer,
					"sticky_cc", prof.CLIVersion,
					"body_ep", bodyEP,
					"sticky_ep", fp.Entrypoint)
			}
		}
		if !signedThinking || identityMismatch || !bodyVerOK || bodyVer != prof.CLIVersion {
			mimicry.AlignBillingCLIVersion(body, prof.CLIVersion)
		}
		if fp.Entrypoint != "" {
			mimicry.AlignBillingEntrypoint(body, fp.Entrypoint)
		}
		if fp.ClientID != "" {
			sid := sessionUUID(SessionHash(body))
			if sid == "" {
				sid = promptID
			}
			mimicry.RewriteUserIDOnly(body, fp.ClientID, acc.Extra.AccountUUID, sid)
		}
	}

	if opts.CountTokens {
		mimicry.StripCountTokensExtras(body)
	}

	thinkingOn := hasThinking(body)
	signedThinking := mimicry.HasSignedThinking(body)
	fastMode := false
	if sp, _ := body["speed"].(string); strings.EqualFold(sp, "fast") {
		fastMode = true
	}
	beta := mimicry.ComputeBetas(opts.Model, mimicry.BetaOptions{
		ThinkingEnabled: thinkingOn || signedThinking,
		RedactThinking:  g.cfg.Mimicry.RedactThinking,
		CountTokens:     opts.CountTokens,
		Auxiliary:       opts.CountTokens,
		CacheTTL1h:      cacheTTLIs1h(body),
		FastMode:        fastMode,
		CLIVersion:      prof.CLIVersion,
	})
	if !opts.IsCC {
		if in := opts.ClientHeaders.Get("anthropic-beta"); in != "" {
			beta = mimicry.MergeBetas(beta, in)
		}
	}
	// First turn of a conversation: emit the input_prompt telemetry marker
	// (carries the chain's cc_prompt_id, exactly like the captured stream).
	if g.telemetry != nil && isNewConversation {
		sid := sessionUUID(opts.SessionHash)
		if sid == "" {
			sid = promptID
		}
		g.telemetry.NotifyConversationStart(acc, sid, opts.Model, beta, promptID, len(mimicry.FirstUserText(body)))
	}

	// OAuth non-stream /v1/messages is its own RPM lane and 429s with no
	// reset headers while stream=true on the same account returns 200.
	// Promote stream=false generations to SSE upstream and fold back to JSON.
	aggregateStream := false
	upstreamStream := opts.Stream
	if !opts.CountTokens && !opts.Stream {
		body["stream"] = true
		upstreamStream = true
		aggregateStream = true
	}

	// count_tokens goes to its own endpoint (and never consumes a
	// generation); everything else to /v1/messages?beta=true.
	target := strings.TrimRight(g.upstreamBase, "/") + "/v1/messages?beta=true"
	if opts.CountTokens {
		target = strings.TrimRight(g.upstreamBase, "/") + "/v1/messages/count_tokens"
	}
	sessionHdr := promptID
	client := &http.Client{
		Transport: SharedOrderedTransport(geo.ProxyURL),
		Timeout:   0, // streaming: rely on request context
	}

	strippedThinking := false
	headerlessTries := 0
	var resp *http.Response
	var lastPayload []byte
	for {
		payload, err := mimicry.EncodeBody(body)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "api_error", "encode body: "+err.Error())
			return true, nil
		}
		lastPayload = payload
		upstream, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "api_error", err.Error())
			return true, nil
		}
		upstream.Header = BuildUpstreamHeaders(HeaderBuildInput{
			Token:          token,
			Beta:           beta,
			Profile:        prof,
			UserAgent:      orDefault(fp.UserAgent, prof.UserAgent),
			SDKVersion:     orDefault(fp.SDKVersion, prof.SDKVersion),
			OS:             fp.OS,
			Arch:           fp.Arch,
			Runtime:        fp.Runtime,
			RuntimeVersion: fp.RuntimeVersion,
			SessionID:      sessionHdr,
			ClientReqID:    mimicry.NewUUID(),
			AcceptLanguage: geo.Language,
			// Pool OAuth accounts always stamp the sticky identity. Passthrough
			// of inbound UA/OS/Arch is what mixed 2.1.246 genuine CLI with
			// 2.1.241 Linux/arm64 mimic on the same token.
			Mimic:         true,
			DispatchV2S:   g.cfg.Mimicry.DispatchHeader,
			IsStream:      upstreamStream,
			ClientHeaders: opts.ClientHeaders,
		})
		resp, err = client.Do(upstream)
		if err != nil {
			slog.Warn("upstream_request_error", "account_id", acc.ID, "error", err.Error())
			return false, nil
		}
		if resp.StatusCode == http.StatusBadRequest && !strippedThinking && !opts.CountTokens {
			msg := peekErrBody(resp)
			if classifyErrorBody(msg) == ErrThinkingSig && mimicry.StripThinkingBlocks(body) {
				slog.Warn("thinking_signature_retry", "account_id", acc.ID, "account", acc.Name, "body", truncateStr(msg, 300))
				_ = resp.Body.Close()
				strippedThinking = true
				continue
			}
		}
		if resp.StatusCode == http.StatusTooManyRequests && !opts.CountTokens && headerlessTries < headerlessRetryMax {
			now := time.Now()
			decision := Parse429(resp.Header, now)
			if decision.Window == "" && decision.Reason != "anthropic_429_retry_after" {
				write429Shape(filepath.Join(g.cfg.AccountsDir, "last_429_shape.json"), body, opts, lastPayload, opts.ClientHeaders.Get("User-Agent"))
				_ = resp.Body.Close()
				headerlessTries++
				slog.Warn("headerless_429_retry", "account_id", acc.ID, "n", headerlessTries, "wait_s", int(headerlessRetryWait.Seconds()),
					"stream_sent", strings.Contains(string(lastPayload), `"stream":true`),
					"keys", strings.Join(bodyKeys(body), ","),
					"max_tokens", body["max_tokens"], "n_tools", lenAny(body["tools"]), "n_msgs", lenAny(body["messages"]))
				if heldSlot {
					g.releaseSlot(acc)
					heldSlot = false
				}
				if headerlessRetryWait > 0 {
					timer := time.NewTimer(headerlessRetryWait)
					select {
					case <-ctx.Done():
						timer.Stop()
						return true, nil
					case <-timer.C:
					}
				}
				if !g.acquireSlot(acc) {
					return false, nil
				}
				heldSlot = true
				continue
			}
		}
		break
	}
	defer func() { _ = resp.Body.Close() }()

	// Harvest the unified rate-limit windows from every response (they ride
	// on success responses too) so the console can show 5h/7d quota state.
	if w5, w7 := WindowsFromHeaders(resp.Header, time.Now()); w5 != nil || w7 != nil {
		_ = g.st.Update(acc.ID, func(a *store.Account) {
			if w5 != nil {
				a.RateWindow5h = &store.RateWindow{Utilization: w5.Utilization, ResetAt: w5.ResetAt}
			}
			if w7 != nil {
				a.RateWindow7d = &store.RateWindow{Utilization: w7.Utilization, ResetAt: w7.ResetAt}
			}
		})
	}

	_ = g.st.Update(acc.ID, func(a *store.Account) { now := time.Now(); a.LastUsedAt = &now })

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		// Invalidate cached token; short cooldown lets the refresher heal it.
		g.recordAttempt(acc, opts, resp.StatusCode, start, usageAcc{})
		_ = g.st.Update(acc.ID, func(a *store.Account) { a.Credentials.AccessToken = "" })
		g.cooldown(acc.ID, 10*time.Minute, "oauth_401")
		_ = resp.Body.Close()
		return false, nil

	case resp.StatusCode == http.StatusForbidden:
		msg := readErrBody(resp)
		g.recordAttempt(acc, opts, resp.StatusCode, start, usageAcc{})
		// A geo-blocked 403 is the egress IP's problem, not the account's:
		// misrouting the account through a bad exit must not kill it.
		switch classifyErrorBody(msg) {
		case ErrGeoBlocked:
			geo := g.geoFor(acc)
			proxyName := geo.ProxyName
			if proxyName == "" {
				proxyName = geo.ProxyURL
			}
			g.cooldown(acc.ID, 30*time.Minute, "egress_geo_blocked: "+truncateStr(msg, 160))
			slog.Error("egress_geo_blocked", "account_id", acc.ID,
				"proxy", orDefault(proxyName, "direct"), "body", truncateStr(msg, 300))
		default:
			g.setError(acc.ID, "403 forbidden: "+msg)
			slog.Error("account_403", "account_id", acc.ID, "body", msg)
		}
		return false, nil

	case resp.StatusCode == http.StatusTooManyRequests:
		msg := peekErrBody(resp)
		write429Shape(filepath.Join(g.cfg.AccountsDir, "last_429_shape.json"), body, opts, lastPayload, opts.ClientHeaders.Get("User-Agent"))
		g.recordAttempt(acc, opts, resp.StatusCode, start, usageAcc{})
		now := time.Now()
		decision := Parse429(resp.Header, now)
		fresh, _ := g.st.Get(acc.ID)
		if fresh != nil {
			decision = Enrich429FromAccount(decision, now, windowStat(fresh.RateWindow5h), windowStat(fresh.RateWindow7d))
		}
		slog.Warn("upstream_429",
			"account_id", acc.ID, "reason", decision.Reason, "window", decision.Window,
			"cooldown_s", int(decision.Cooldown.Seconds()),
			"retry_after", resp.Header.Get("Retry-After"),
			"count_tokens", opts.CountTokens, "promoted", aggregateStream,
			"cc", opts.IsCC, "body", truncateStr(msg, 300))
		if mw, ok := ParseModelWindow(resp.Header, now); ok {
			slog.Warn("model_window_limited", "account_id", acc.ID, "window", mw.Window)
		} else if opts.CountTokens {
			slog.Warn("count_tokens_429_skip_cooldown", "account_id", acc.ID)
		} else if decision.Window != "" || decision.Reason == "anthropic_429_retry_after" || decision.Reason == "anthropic_requests_reset" || decision.Reason == "anthropic_unified_reset" {
			g.cooldown(acc.ID, decision.Cooldown, decision.Reason)
		} else {
			g.noteHeaderless(acc.ID, decision.Cooldown)
		}
		return false, &rateLimitEcho{Decision: decision, Body: msg}

	case resp.StatusCode == 529 || resp.StatusCode >= 500:
		g.recordAttempt(acc, opts, resp.StatusCode, start, usageAcc{})
		slog.Warn("upstream_5xx", "account_id", acc.ID, "status", resp.StatusCode)
		_ = resp.Body.Close()
		return false, nil

	case resp.StatusCode >= 400:
		msg := readErrBody(resp)
		g.recordAttempt(acc, opts, resp.StatusCode, start, usageAcc{})
		slog.Warn("forward",
			"account", acc.Name, "model", opts.Model, "status", resp.StatusCode,
			"stream", opts.Stream, "ms", time.Since(start).Milliseconds(),
			"body", truncateStr(msg, 300), "cc", opts.IsCC)
		// Account-attributable failures inside a 4xx body: billing exhausted
		// cools the account down; model-access gaps only fail this attempt
		// over to the next account. Everything else is client error and
		// passes through unchanged.
		switch classifyErrorBody(msg) {
		case ErrBilling:
			g.cooldown(acc.ID, 6*time.Hour, "billing_exhausted: "+truncateStr(msg, 160))
			slog.Warn("account_billing_exhausted", "account_id", acc.ID, "body", truncateStr(msg, 300))
			return false, nil
		case ErrModelAccess:
			slog.Warn("account_model_access", "account_id", acc.ID, "model", opts.Model, "body", truncateStr(msg, 300))
			return false, nil
		}
		copyHeaders(w, resp)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.WriteString(w, msg)
		return true, nil
	}

	// Success path.
	g.chain.Bind(opts.SessionHash, acc.ID)
	if opts.Stream {
		copyHeaders(w, resp)
		u := g.relaySSE(w, resp)
		g.recordAttempt(acc, opts, resp.StatusCode, start, u)
	} else if aggregateStream && isSSEResponse(resp) {
		data, u, err := collectAnthropicSSE(resp.Body)
		if err != nil {
			slog.Warn("sse_aggregate_failed", "account_id", acc.ID, "error", err.Error())
			g.recordAttempt(acc, opts, resp.StatusCode, start, u)
			writeErr(w, http.StatusBadGateway, "api_error", "upstream stream aggregate failed: "+err.Error())
			return true, nil
		}
		if rid := resp.Header.Get("request-id"); rid != "" {
			w.Header().Set("request-id", rid)
		}
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		g.recordAttempt(acc, opts, http.StatusOK, start, u)
	} else {
		copyHeaders(w, resp)
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(data)
		if opts.CountTokens {
			g.recordAttempt(acc, opts, resp.StatusCode, start, parseCountTokens(data))
		} else {
			g.recordAttempt(acc, opts, resp.StatusCode, start, parseFinalUsage(data))
		}
	}
	// Emit the same per-query telemetry event the real CLI records (a token
	// count is not a model query, so it stays out of telemetry).
	if g.telemetry != nil && !opts.CountTokens {
		if in, out := g.ledger.lastUsage(); in >= 0 {
			g.telemetry.NotifyQuery(acc, opts.Model, opts.Stream, in, out, hasThinking(body))
		}
	}
	return true, nil
}

func windowStat(rw *store.RateWindow) *WindowStat {
	if rw == nil {
		return nil
	}
	return &WindowStat{Utilization: rw.Utilization, ResetAt: rw.ResetAt}
}

// recordAttempt writes one per-account request record; token fields stay zero
// when upstream never returned usage (failed attempt).
func (g *Gateway) recordAttempt(acc *store.Account, opts forwardOpts, status int, start time.Time, u usageAcc) {
	g.ledger.record(UsageRecord{
		Time: start, AccountID: acc.ID, AccountName: acc.Name,
		Model: opts.Model, Stream: opts.Stream, Status: status,
		DurationMS: time.Since(start).Milliseconds(),
		Input: u.input, Output: u.output, CacheWrite: u.cacheWrite, CacheRead: u.cacheRead,
	})
	if status >= 400 {
		slog.Warn("forward",
			"account", acc.Name, "model", opts.Model, "status", status,
			"stream", opts.Stream, "ms", time.Since(start).Milliseconds())
		return
	}
	slog.Info("forward",
		"account", acc.Name, "model", opts.Model, "status", status,
		"stream", opts.Stream, "ms", time.Since(start).Milliseconds(),
		"in", u.input, "out", u.output, "cache_w", u.cacheWrite, "cache_r", u.cacheRead,
		"cc", opts.IsCC, "ua", shortUA(opts.ClientHeaders.Get("User-Agent")))
}

// usageAcc accumulates the usage object of one upstream response. input and
// the cache counters are absolute per message (last value wins); output_tokens
// in message_delta is cumulative, so it is tracked as a running max.
type usageAcc struct {
	input, output, cacheWrite, cacheRead int64
}

// relaySSE streams events to the client and harvests usage.
func (g *Gateway) relaySSE(w http.ResponseWriter, resp *http.Response) usageAcc {
	flusher, _ := w.(http.Flusher)
	w.WriteHeader(http.StatusOK)
	var u usageAcc
	buf := make([]byte, 32*1024)
	var line strings.Builder
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			_, _ = w.Write(chunk)
			if flusher != nil {
				flusher.Flush()
			}
			u = scanUsage(line, chunk, u)
		}
		if err != nil {
			break
		}
	}
	return u
}

// scanUsage extracts the usage object from SSE events: message_start carries
// input + cache counters, message_delta the cumulative output count.
func scanUsage(acc strings.Builder, chunk []byte, u usageAcc) usageAcc {
	for _, b := range chunk {
		if b == '\n' {
			line := strings.TrimSpace(acc.String())
			acc.Reset()
			if strings.HasPrefix(line, "data:") {
				var ev struct {
					Type  string `json:"type"`
					Usage *struct {
						InputTokens              *int64 `json:"input_tokens"`
						OutputTokens             *int64 `json:"output_tokens"`
						CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens"`
						CacheReadInputTokens     *int64 `json:"cache_read_input_tokens"`
					} `json:"usage"`
				}
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "data:")), &ev) == nil && ev.Usage != nil {
					if ev.Usage.InputTokens != nil {
						u.input = *ev.Usage.InputTokens
					}
					if ev.Usage.OutputTokens != nil && *ev.Usage.OutputTokens > u.output {
						u.output = *ev.Usage.OutputTokens
					}
					if ev.Usage.CacheCreationInputTokens != nil {
						u.cacheWrite = *ev.Usage.CacheCreationInputTokens
					}
					if ev.Usage.CacheReadInputTokens != nil {
						u.cacheRead = *ev.Usage.CacheReadInputTokens
					}
				}
			}
			continue
		}
		acc.WriteByte(b)
	}
	return u
}

// parseFinalUsage reads the usage object out of a non-streaming response body.
func parseFinalUsage(data []byte) usageAcc {
	var v struct {
		Usage *struct {
			InputTokens              *int64 `json:"input_tokens"`
			OutputTokens             *int64 `json:"output_tokens"`
			CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens"`
			CacheReadInputTokens     *int64 `json:"cache_read_input_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(data, &v) != nil || v.Usage == nil {
		return usageAcc{}
	}
	var u usageAcc
	if v.Usage.InputTokens != nil {
		u.input = *v.Usage.InputTokens
	}
	if v.Usage.OutputTokens != nil {
		u.output = *v.Usage.OutputTokens
	}
	if v.Usage.CacheCreationInputTokens != nil {
		u.cacheWrite = *v.Usage.CacheCreationInputTokens
	}
	if v.Usage.CacheReadInputTokens != nil {
		u.cacheRead = *v.Usage.CacheReadInputTokens
	}
	return u
}

// parseCountTokens reads the top-level input_tokens of a count_tokens
// response into the ledger accumulator.
func parseCountTokens(data []byte) usageAcc {
	var v struct {
		InputTokens *int64 `json:"input_tokens"`
	}
	if json.Unmarshal(data, &v) != nil || v.InputTokens == nil {
		return usageAcc{}
	}
	return usageAcc{input: *v.InputTokens}
}

// ---- small helpers ----

func writeErr(w http.ResponseWriter, status int, typ, msg string) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":  "error",
		"error": map[string]any{"type": typ, "message": msg},
	})
}

func copyHeaders(w http.ResponseWriter, resp *http.Response) {
	for k, vv := range resp.Header {
		lk := strings.ToLower(k)
		if lk == "content-length" || lk == "transfer-encoding" || lk == "content-encoding" || lk == "connection" {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	if ct := resp.Header.Get("content-type"); ct != "" {
		w.Header().Set("content-type", ct)
	}
}

func readErrBody(resp *http.Response) string {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	return string(raw)
}

// peekErrBody reads the error payload and puts it back so a later
// readErrBody / client copy still sees the same bytes.
func peekErrBody(resp *http.Response) string {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	return string(raw)
}

func hasThinking(body map[string]any) bool {
	t, ok := body["thinking"].(map[string]any)
	if !ok {
		return false
	}
	switch t["type"] {
	case "enabled", "adaptive":
		return true
	}
	return false
}

func cacheTTLIs1h(body map[string]any) bool {
	// 1h mode is signaled by any cache_control carrying ttl "1h".
	raw, _ := json.Marshal(body)
	return bytes.Contains(raw, []byte(`"ttl":"1h"`)) || bytes.Contains(raw, []byte(`"ttl": "1h"`))
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

// sessionUUID returns the session hash when it is UUID-shaped (real CLI
// session ids are UUIDs; synthesized ones must be too).
func sessionUUID(hash string) string {
	if isUUIDShape(hash) {
		return hash
	}
	return ""
}

func isUUIDShape(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// acceptableUA reports whether ua is a well-formed official claude-cli
// User-Agent: `claude-cli/X.Y.Z` or `claude-cli/X.Y.Z (external, cli)`
// (also sdk-cli / claude-vscode / extra agent-sdk, client-app, workload
// tags). Used as a diagnostic filter — inbound UAs are no longer written
// onto the per-account fingerprint.
func acceptableUA(ua string) bool {
	ua = strings.TrimSpace(ua)
	if ua == "" || len(ua) > 256 {
		return false
	}
	if !strings.HasPrefix(ua, "claude-cli/") {
		return false
	}
	rest := strings.TrimPrefix(ua, "claude-cli/")
	ver, suffix := splitCLIVersion(rest)
	if !cliVersionShape(ver) {
		return false
	}
	if suffix != "" && !validCLISuffix(suffix) {
		return false
	}
	if t, ok := versionTriple(ua); ok {
		if p, ok2 := versionTriple(profile.Default.UserAgent); ok2 {
			if t[0] > p[0]+2 {
				return false
			}
		}
	}
	return true
}

func splitCLIVersion(rest string) (ver, suffix string) {
	rest = strings.TrimSpace(rest)
	if i := strings.IndexByte(rest, ' '); i >= 0 {
		return rest[:i], strings.TrimSpace(rest[i+1:])
	}
	return rest, ""
}

func cliVersionShape(ver string) bool {
	dots := 0
	digits := 0
	for _, c := range ver {
		if c == '.' {
			dots++
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		digits++
	}
	return dots == 2 && digits >= 3 && len(ver) >= 5
}

func validCLISuffix(suffix string) bool {
	if !strings.HasPrefix(suffix, "(") || !strings.HasSuffix(suffix, ")") {
		return false
	}
	inner := strings.TrimSpace(suffix[1 : len(suffix)-1])
	return strings.HasPrefix(inner, "external,")
}

// newerVersion compares product/x.y.z versions of the same product.
func cliVersionMismatch(a, b string) bool {
	ta, oka := versionTriple(a)
	tb, okb := versionTriple(b)
	if !oka || !okb {
		return false
	}
	return ta != tb
}

func newerVersion(newUA, oldUA string) bool {
	if extractProduct(newUA) != extractProduct(oldUA) || extractProduct(newUA) == "" {
		return false
	}
	n, ok1 := versionTriple(newUA)
	o, ok2 := versionTriple(oldUA)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if n[i] != o[i] {
			return n[i] > o[i]
		}
	}
	return false
}

func cliVersionFromUA(ua string) (string, bool) {
	t, ok := versionTriple(ua)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d", t[0], t[1], t[2]), true
}

func extractProduct(ua string) string {
	if i := strings.IndexByte(ua, '/'); i > 0 {
		return strings.ToLower(ua[:i])
	}
	return ""
}

func versionTriple(ua string) ([3]int, bool) {
	var t [3]int
	i := strings.IndexByte(ua, '/')
	if i < 0 {
		return t, false
	}
	rest := ua[i+1:]
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		rest = rest[:sp]
	}
	parts := strings.Split(rest, ".")
	if len(parts) < 3 {
		return t, false
	}
	for j := 0; j < 3; j++ {
		if parts[j] == "" {
			return t, false
		}
		n := 0
		for _, c := range parts[j] {
			if c < '0' || c > '9' {
				return t, false
			}
			n = n*10 + int(c-'0')
		}
		t[j] = n
	}
	return t, true
}

// shortUA condenses a User-Agent for one-line logging.
func shortUA(ua string) string {
	if i := strings.IndexByte(ua, ' '); i > 0 {
		ua = ua[:i]
	}
	if len(ua) > 40 {
		ua = ua[:40]
	}
	return ua
}
