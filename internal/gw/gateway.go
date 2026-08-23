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
	"strings"
	"sync"
	"time"

	"claudetoapi/internal/config"
	"claudetoapi/internal/mimicry"
	"claudetoapi/internal/oauth"
	"claudetoapi/internal/profile"
	"claudetoapi/internal/store"
)

const upstreamMessagesURL = "https://api.anthropic.com/v1/messages?beta=true"

// Gateway is the forwarding core.
type Gateway struct {
	cfg       *config.Config
	st        *store.Store
	chain     *Chain
	telemetry *TelemetryManager

	// tokenMu serializes refresh per account.
	tokenMu sync.Mutex
	// slots enforces per-account concurrency caps.
	slots sync.Map

	usage struct {
		mu     sync.Mutex
		input  map[int64]int64
		output map[int64]int64
		reqs   map[int64]int64
		lastIn int64
		lastOut int64
	}
}

func New(cfg *config.Config, st *store.Store) *Gateway {
	g := &Gateway{
		cfg:       cfg,
		st:        st,
		chain:     NewChain(),
		telemetry: nil,
	}
	g.usage.input = map[int64]int64{}
	g.usage.output = map[int64]int64{}
	g.usage.reqs = map[int64]int64{}
	return g
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
	g.tokenMu.Lock()
	defer g.tokenMu.Unlock()

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
		// Refresh failures are usually transient or revocation; cool the
		// account down rather than hard-disabling on the first strike.
		g.cooldown(acc.ID, 10*time.Minute, "oauth_refresh_failed: "+err.Error())
		return "", fmt.Errorf("account %d refresh: %w", acc.ID, err)
	}
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

// pick chooses an account: sticky first, then least-recently-used active.
func (g *Gateway) pick(sessionHash string, exclude map[int64]bool) *store.Account {
	now := time.Now()
	if id, ok := g.chain.Sticky(sessionHash); ok && !exclude[id] {
		if acc, err := g.st.Get(id); err == nil && acc.Active(now) {
			return acc
		}
	}
	var best *store.Account
	for _, acc := range g.st.Snapshot() {
		if exclude[acc.ID] || !acc.Active(now) {
			continue
		}
		if best == nil {
			best = acc
			continue
		}
		bt, at := best.LastUsedAt, acc.LastUsedAt
		if at == nil || (bt != nil && at.Before(*bt)) {
			best = acc
		}
	}
	return best
}

// ---- fingerprint resolution ----

// resolveFingerprint returns the per-account identity, creating it lazily and
// adopting newer real-client UAs (version-only drift) with the same poison
// guards sub2api learned the hard way (implausible versions cause permanent
// headerless-429 loops upstream).
func (g *Gateway) resolveFingerprint(acc *store.Account, clientUA string) (fp *store.Fingerprint, prof *profile.Profile) {
	prof = profile.Default
	if p, ok := profile.Registry[g.cfg.ProfileName]; ok {
		prof = p
	}

	if acc.Fingerprint != nil && acc.Fingerprint.ClientID != "" {
		fp = acc.Fingerprint
		// Adopt a newer well-formed claude-cli UA from real traffic.
		if acceptableUA(clientUA) && newerVersion(clientUA, fp.UserAgent) {
			_ = g.st.Update(acc.ID, func(a *store.Account) {
				if a.Fingerprint != nil {
					a.Fingerprint.UserAgent = strings.TrimSpace(clientUA)
					a.Fingerprint.SDKVersion = prof.SDKVersion
					a.Fingerprint.UpdatedAt = time.Now().Unix()
				}
			})
			fp.UserAgent = strings.TrimSpace(clientUA)
		}
		return fp, prof
	}

	entry := g.cfg.Mimicry.DefaultEntrypoint
	if entry == "" {
		entry = "cli"
	}
	newFP := &store.Fingerprint{
		ClientID:   newClientID(),
		Entrypoint: entry,
		Profile:    prof.Name,
		UserAgent:  prof.UserAgent,
		SDKVersion: prof.SDKVersion,
		UpdatedAt:  time.Now().Unix(),
	}
	_ = g.st.Update(acc.ID, func(a *store.Account) { a.Fingerprint = newFP })
	return newFP, prof
}

// provisionFingerprint creates the persistent identity for a new account
// with the requested entrypoint persona.
func (g *Gateway) provisionFingerprint(acc *store.Account, entrypoint string) *store.Fingerprint {
	if acc.Fingerprint != nil && acc.Fingerprint.ClientID != "" {
		return acc.Fingerprint
	}
	prof := profile.Default
	if p, ok := profile.Registry[g.cfg.ProfileName]; ok {
		prof = p
	}
	if entrypoint == "" {
		entrypoint = g.cfg.Mimicry.DefaultEntrypoint
	}
	fp := &store.Fingerprint{
		ClientID:   newClientID(),
		Entrypoint: entrypoint,
		Profile:    prof.Name,
		UserAgent:  prof.UserAgent,
		SDKVersion: prof.SDKVersion,
		UpdatedAt:  time.Now().Unix(),
	}
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
	for i := 0; i < attempts; i++ {
		acc := g.pick(sessionHash, exclude)
		if acc == nil {
			writeErr(w, http.StatusServiceUnavailable, "overloaded_error", "no available upstream accounts")
			return
		}
		done := g.forwardOnce(w, r, acc, body, forwardOpts{
			IsCC: isCC, Stream: stream, Model: model, SessionHash: sessionHash, ClientHeaders: r.Header,
		})
		if done {
			return
		}
		exclude[acc.ID] = true
	}
	writeErr(w, http.StatusServiceUnavailable, "overloaded_error", "all upstream attempts failed")
}

type forwardOpts struct {
	IsCC          bool
	Stream        bool
	Model         string
	SessionHash   string
	ClientHeaders http.Header
	CountTokens   bool
}

// forwardOnce sends the request through one account. It returns true when
// the response has been fully handled (success or terminal error); false
// when the caller should fail over to another account.
func (g *Gateway) forwardOnce(w http.ResponseWriter, r *http.Request, acc *store.Account, body map[string]any, opts forwardOpts) bool {
	ctx := r.Context()

	// Per-account concurrency guard: real CLI processes run 1-3 parallel
	// sessions; a pool account fanning out to dozens at once is a pattern.
	if !g.acquireSlot(acc) {
		return false
	}
	defer g.releaseSlot(acc)

	token, err := g.accessToken(ctx, acc)
	if err != nil {
		return false // account unusable now; fail over
	}

	// Telemetry bypass: lazily start the account's background runner
	// (flag-eval pulls + first-party events) on its egress path.
	if g.telemetry != nil {
		g.telemetry.EnsureStarted(acc, token)
	}

	geo := g.geoFor(acc)
	// Align the dateline date with the exit IP's calendar day: the CLI stamps
	// its local date into the prompt, so a US egress must carry the US date.
	if geo.Timezone != nil {
		mimicry.ShiftDatelines(body, time.Now().In(geo.Timezone).Format("2006-01-02"))
	}

	fp, prof := g.resolveFingerprint(acc, opts.ClientHeaders.Get("User-Agent"))
	persona := mimicry.PersonaFor(fp.Entrypoint)
	// chain.Next advances the conversation chain: promptID stays stable,
	// prevReqID links to the previous request (first request: empty).
	promptID, prevReqID, _ := g.chain.Next(opts.SessionHash)

	thinkingOn := hasThinking(body)
	fastMode := false
	if sp, _ := body["speed"].(string); strings.EqualFold(sp, "fast") {
		fastMode = true
	}
	beta := mimicry.ComputeBetas(opts.Model, mimicry.BetaOptions{
		ThinkingEnabled: thinkingOn,
		RedactThinking:  g.cfg.Mimicry.RedactThinking,
		CountTokens:     opts.CountTokens,
		Auxiliary:       opts.CountTokens,
		CacheTTL1h:      cacheTTLIs1h(body),
		FastMode:        fastMode,
	})

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
		})
	} else {
		// Real CLI traffic: only rewrite the device identity so the account
		// presents one stable machine.
		if fp.ClientID != "" {
			sid := sessionUUID(SessionHash(body))
			if sid == "" {
				sid = promptID
			}
			mimicry.RewriteUserIDOnly(body, fp.ClientID, acc.Extra.AccountUUID, sid)
		}
	}

	payload, err := mimicry.EncodeBody(body)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "api_error", "encode body: "+err.Error())
		return true
	}

	upstream, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamMessagesURL, bytes.NewReader(payload))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "api_error", err.Error())
		return true
	}
	sessionHdr := promptID
	upstream.Header = BuildUpstreamHeaders(HeaderBuildInput{
		Token:         token,
		Beta:          beta,
		Profile:       prof,
		UserAgent:     orDefault(fp.UserAgent, prof.UserAgent),
		SDKVersion:    orDefault(fp.SDKVersion, prof.SDKVersion),
		SessionID:     sessionHdr,
		ClientReqID:   mimicry.NewUUID(),
		AcceptLanguage: geo.Language,
		Mimic:         !opts.IsCC,
		DispatchV2S:   g.cfg.Mimicry.DispatchHeader,
		IsStream:      opts.Stream,
		ClientHeaders: opts.ClientHeaders,
	})

	// Ordered transport: header wire order matches the real CLI (Go's own
	// writer would alphabetize them), connections pooled per proxy.
	client := &http.Client{
		Transport: SharedOrderedTransport(geo.ProxyURL),
		Timeout:   0, // streaming: rely on request context
	}
	resp, err := client.Do(upstream)
	if err != nil {
		slog.Warn("upstream_request_error", "account_id", acc.ID, "error", err.Error())
		return false // network error: fail over
	}
	defer func() { _ = resp.Body.Close() }()

	_ = g.st.Update(acc.ID, func(a *store.Account) { now := time.Now(); a.LastUsedAt = &now })

	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		// Invalidate cached token; short cooldown lets the refresher heal it.
		_ = g.st.Update(acc.ID, func(a *store.Account) { a.Credentials.AccessToken = "" })
		g.cooldown(acc.ID, 10*time.Minute, "oauth_401")
		_ = resp.Body.Close()
		return false

	case resp.StatusCode == http.StatusForbidden:
		msg := readErrBody(resp)
		g.setError(acc.ID, "403 forbidden: "+msg)
		slog.Error("account_403", "account_id", acc.ID, "body", msg)
		return false

	case resp.StatusCode == http.StatusTooManyRequests:
		decision := Parse429(resp.Header, time.Now())
		if mw, ok := ParseModelWindow(resp.Header, time.Now()); ok {
			slog.Warn("model_window_limited", "account_id", acc.ID, "window", mw.Window)
		} else {
			g.cooldown(acc.ID, decision.Cooldown, decision.Reason)
		}
		_ = resp.Body.Close()
		return false

	case resp.StatusCode == 529 || resp.StatusCode >= 500:
		slog.Warn("upstream_5xx", "account_id", acc.ID, "status", resp.StatusCode)
		_ = resp.Body.Close()
		return false

	case resp.StatusCode >= 400:
		// Client-attributable errors pass through unchanged.
		copyHeaders(w, resp)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return true
	}

	// Success path.
	g.chain.Bind(opts.SessionHash, acc.ID)
	copyHeaders(w, resp)
	if opts.Stream {
		g.relaySSE(w, resp, acc.ID)
	} else {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(data)
		g.recordUsage(acc.ID, data, nil)
	}
	// Emit the same per-query telemetry event the real CLI records.
	if g.telemetry != nil {
		if in, out := g.lastUsageFor(acc.ID); in >= 0 {
			g.telemetry.NotifyQuery(acc, opts.Model, opts.Stream, in, out)
		}
	}
	return true
}

// relaySSE streams events to the client and harvests usage.
func (g *Gateway) relaySSE(w http.ResponseWriter, resp *http.Response, accountID int64) {
	flusher, _ := w.(http.Flusher)
	w.WriteHeader(http.StatusOK)
	var usageIn, usageOut int64
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
			usageIn, usageOut = scanUsage(line, chunk, usageIn, usageOut)
		}
		if err != nil {
			break
		}
	}
	g.recordUsageCounts(accountID, usageIn, usageOut)
}

// scanUsage extracts input/output tokens from SSE usage events.
func scanUsage(acc strings.Builder, chunk []byte, in, out int64) (int64, int64) {
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
						in = *ev.Usage.InputTokens
					}
					if ev.Usage.OutputTokens != nil {
						out += *ev.Usage.OutputTokens
					}
					if ev.Usage.CacheCreationInputTokens != nil {
						in += *ev.Usage.CacheCreationInputTokens
					}
					if ev.Usage.CacheReadInputTokens != nil {
						in += *ev.Usage.CacheReadInputTokens
					}
				}
			}
			continue
		}
		acc.WriteByte(b)
	}
	return in, out
}

func (g *Gateway) recordUsage(accountID int64, data []byte, _ []byte) {
	var v struct {
		Usage *struct {
			InputTokens  *int64 `json:"input_tokens"`
			OutputTokens *int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(data, &v) == nil && v.Usage != nil {
		in, out := int64(0), int64(0)
		if v.Usage.InputTokens != nil {
			in = *v.Usage.InputTokens
		}
		if v.Usage.OutputTokens != nil {
			out = *v.Usage.OutputTokens
		}
		g.recordUsageCounts(accountID, in, out)
	}
}

// recordUsageCounts accumulates per-account usage and remembers the most
// recent (input, output) pair so the telemetry path can report per-query
// numbers like the CLI does.
func (g *Gateway) recordUsageCounts(accountID int64, in, out int64) {
	g.usage.mu.Lock()
	defer g.usage.mu.Unlock()
	g.usage.input[accountID] += in
	g.usage.output[accountID] += out
	g.usage.reqs[accountID]++
	g.usage.lastIn = in
	g.usage.lastOut = out
}

// lastUsageFor returns the most recently recorded query usage.
func (g *Gateway) lastUsageFor(accountID int64) (int64, int64) {
	g.usage.mu.Lock()
	defer g.usage.mu.Unlock()
	return g.usage.lastIn, g.usage.lastOut
}

// UsageSnapshot returns per-account counters (admin endpoint).
func (g *Gateway) UsageSnapshot() map[int64][3]int64 {
	g.usage.mu.Lock()
	defer g.usage.mu.Unlock()
	out := map[int64][3]int64{}
	for id, r := range g.usage.reqs {
		out[id] = [3]int64{r, g.usage.input[id], g.usage.output[id]}
	}
	return out
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

// acceptableUA guards the fingerprint store against poisoned UAs (wrong
// shape, local builds, implausible sentinel versions) and against versions
// more than 2 majors ahead of the profile (a 999.x sentinel gets adopted and
// then triggers permanent headerless-429 loops upstream).
func acceptableUA(ua string) bool {
	ua = strings.TrimSpace(ua)
	if ua == "" || len(ua) > 256 {
		return false
	}
	if !strings.HasPrefix(ua, "claude-cli/") {
		return false
	}
	rest := strings.TrimPrefix(ua, "claude-cli/")
	dots := 0
	for _, c := range rest {
		if c == '.' {
			dots++
			continue
		}
		if c < '0' || c > '9' {
			return false // rejects -local / +build suffixes
		}
	}
	if dots != 2 || len(rest) < 5 {
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

// newerVersion compares product/x.y.z versions of the same product.
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
	parts := strings.Split(rest, ".")
	if len(parts) < 3 {
		return t, false
	}
	for j := 0; j < 3; j++ {
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
