package gw

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"claudetoapi/internal/config"
	"claudetoapi/internal/mimicry"
	"claudetoapi/internal/oauth"
	"claudetoapi/internal/profile"
	"claudetoapi/internal/store"
	"claudetoapi/internal/tlsfp"
)

// Admin exposes account management behind the admin key.
type Admin struct {
	cfg       *config.Config
	cfgPath   string // config file for runtime settings persistence ("" = in-memory only)
	st        *store.Store
	gw        *Gateway
	version   string
	settingsMu sync.Mutex
}

// NewAdmin builds the admin API; ver is reported by /admin/info.
func NewAdmin(cfg *config.Config, st *store.Store, g *Gateway, ver string) *Admin {
	return &Admin{cfg: cfg, st: st, gw: g, version: ver}
}

// SetConfigPath enables persisting runtime settings back to the config file.
func (a *Admin) SetConfigPath(p string) { a.cfgPath = p }

// Mount registers admin routes on mux. All routes require X-Admin-Key.
func (a *Admin) Mount(mux *http.ServeMux) {
	wrap := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !secureEqual(r.Header.Get("X-Admin-Key"), a.cfg.AdminKey) {
				writeErr(w, http.StatusUnauthorized, "authentication_error", "invalid admin key")
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /admin/accounts", wrap(a.list))
	mux.HandleFunc("POST /admin/accounts", wrap(a.add))
	mux.HandleFunc("DELETE /admin/accounts/{id}", wrap(a.remove))
	mux.HandleFunc("POST /admin/accounts/{id}/refresh", wrap(a.refresh))
	mux.HandleFunc("GET /admin/oauth/url", wrap(a.oauthBegin))
	mux.HandleFunc("POST /admin/oauth/complete", wrap(a.oauthComplete))
	mux.HandleFunc("GET /admin/usage", wrap(a.usage))
	mux.HandleFunc("GET /admin/usage/logs", wrap(a.usageLogs))
	mux.HandleFunc("GET /admin/info", wrap(a.info))
	mux.HandleFunc("PATCH /admin/accounts/{id}", wrap(a.patch))
	mux.HandleFunc("PUT /admin/settings", wrap(a.putSettings))
	mux.HandleFunc("POST /admin/accounts/{id}/reauthorize", wrap(a.reauthorize))
	mux.HandleFunc("POST /admin/proxies/test", wrap(a.testProxy))
}

// patch updates editable account fields: proxy (pool name or raw URL),
// entrypoint persona, name and concurrency.
func (a *Admin) patch(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	var req struct {
		Name        *string `json:"name"`
		Proxy       *string `json:"proxy"`     // pool name, raw URL or "" to clear
		Entrypoint  *string `json:"entrypoint"`
		Concurrency *int    `json:"concurrency"`
		OutputStyle *string `json:"output_style"` // "", "concise", "proactive"; "" falls back to the global default
		ClearError  bool    `json:"clear_error"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	// Validate a named proxy reference before storing it.
	if req.Proxy != nil && *req.Proxy != "" && !strings.Contains(*req.Proxy, "://") {
		found := false
		for _, p := range a.cfg.Proxies {
			if p.Name == *req.Proxy {
				found = true
				break
			}
		}
		if !found {
			writeErr(w, http.StatusBadRequest, "invalid_request_error", "unknown proxy pool name: "+*req.Proxy)
			return
		}
	}
	if err := a.st.Update(id, func(x *store.Account) {
		if req.Name != nil && *req.Name != "" {
			x.Name = *req.Name
		}
		if req.Proxy != nil {
			x.Proxy = *req.Proxy
			x.ProxyURL = ""
		}
		if req.Entrypoint != nil && *req.Entrypoint != "" {
			if x.Fingerprint != nil {
				x.Fingerprint.Entrypoint = *req.Entrypoint
			}
		}
		if req.Concurrency != nil && *req.Concurrency > 0 {
			x.Concurrency = *req.Concurrency
		}
		if req.OutputStyle != nil {
			v := strings.ToLower(strings.TrimSpace(*req.OutputStyle))
			if v == "default" {
				v = ""
			}
			if !mimicry.ValidStyleKey(v) {
				writeErr(w, http.StatusBadRequest, "invalid_request_error",
					`unknown output_style: use "", "concise" or "proactive"`)
				return
			}
			x.OutputStyle = v
		}
		if req.ClearError {
			x.Status = "active"
			x.Error = ""
			x.RateLimitedUntil = nil
			x.RateLimitReason = ""
		}
	}); err != nil {
		writeErr(w, http.StatusNotFound, "not_found_error", err.Error())
		return
	}
	acc, _ := a.st.Get(id)
	writeJSON(w, http.StatusOK, map[string]any{"id": acc.ID, "proxy": acc.Proxy, "name": acc.Name})
}

// testProxy verifies a proxy spec (pool name or URL) by dialing
// api.anthropic.com:443 through it with the fingerprinted handshake.
func (a *Admin) testProxy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Proxy string `json:"proxy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	spec := req.Proxy
	resolved := ""
	for _, p := range a.cfg.Proxies {
		if p.Name == spec {
			resolved = p.URL
			break
		}
	}
	if resolved == "" {
		resolved = spec // raw URL
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	start := time.Now()
	conn, err := tlsfp.Dial(ctx, "tcp", "api.anthropic.com:443", resolved)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "elapsed_ms": time.Since(start).Milliseconds()})
		return
	}
	_ = conn.Close()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "elapsed_ms": time.Since(start).Milliseconds()})
}

// info returns console metadata (version, profile pairing, runtime flags).
func (a *Admin) info(w http.ResponseWriter, r *http.Request) {
	prof := profile.Default
	if p, ok := profile.Registry[a.cfg.ProfileName]; ok {
		prof = p
	}
	proxies := make([]map[string]any, 0, len(a.cfg.Proxies))
	for _, p := range a.cfg.Proxies {
		proxies = append(proxies, map[string]any{
			"name":     p.Name,
			"timezone": p.Timezone,
			"language": p.Language,
			"url":      maskProxyURL(p.URL),
		})
	}
	dials, reuses, dropped := SharedOrderedTransport("").Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":            a.version,
		"listen":             a.cfg.Listen,
		"profile":            prof.Name,
		"sdk_version":        prof.SDKVersion,
		"default_proxy":      a.cfg.DefaultProxyURL != "",
		"dispatch_header":    a.cfg.Mimicry.DispatchHeader,
		"output_style":       a.cfg.Mimicry.OutputStyle,
		"telemetry":          a.gw.Telemetry().Enabled(),
		"telemetry_runners":  a.gw.Telemetry().Stats(),
		"accounts":           len(a.st.Snapshot()),
		"proxies":            proxies,
		"conn_pool":          map[string]uint64{"dials": dials, "reuses": reuses, "dropped": dropped},
	})
}

// maskProxyURL hides credentials for display.
func maskProxyURL(u string) string {
	i := strings.Index(u, "@")
	if i < 0 {
		return u
	}
	if scheme := strings.Index(u, "://"); scheme >= 0 {
		return u[:scheme+3] + "***@" + u[i+1:]
	}
	return "***" + u[i:]
}

type config2 = config.Config

func (a *Admin) list(w http.ResponseWriter, r *http.Request) {
	type row struct {
		ID               int64             `json:"id"`
		Name             string            `json:"name"`
		Email            string            `json:"email"`
		Status           string            `json:"status"`
		Error            string            `json:"error,omitempty"`
		RateLimitedUntil *time.Time        `json:"rate_limited_until,omitempty"`
		RateLimitReason  string            `json:"rate_limit_reason,omitempty"`
		Entrypoint       string            `json:"entrypoint"`
		HasRefresh       bool              `json:"has_refresh_token"`
		Proxy            string            `json:"proxy,omitempty"`
		Timezone         string            `json:"timezone,omitempty"`
		Language         string            `json:"language,omitempty"`
		Concurrency      int               `json:"concurrency"`
		RateWindow5h     *store.RateWindow `json:"rate_window_5h,omitempty"`
		RateWindow7d     *store.RateWindow `json:"rate_window_7d,omitempty"`
		OutputStyle      string            `json:"output_style,omitempty"`
	}
	// Expired window snapshots are stale (the window has reset since); drop
	// them from the API response so the console shows "—" instead of 100%.
	now := time.Now()
	prune := func(w *store.RateWindow) *store.RateWindow {
		if w == nil || !now.Before(w.ResetAt) {
			return nil
		}
		return w
	}
	rows := make([]row, 0)
	for _, acc := range a.st.Snapshot() {
		ep := ""
		if acc.Fingerprint != nil {
			ep = acc.Fingerprint.Entrypoint
		}
		geo := a.gw.geoFor(acc)
		tzName := ""
		if geo.Timezone != nil {
			tzName = geo.Timezone.String()
		}
		proxyDisplay := acc.Proxy
		if proxyDisplay == "" && acc.ProxyURL != "" {
			proxyDisplay = maskProxyURL(acc.ProxyURL)
		}
		rows = append(rows, row{
			ID: acc.ID, Name: acc.Name, Email: acc.Extra.Email, Status: acc.Status,
			Error: acc.Error, RateLimitedUntil: acc.RateLimitedUntil, RateLimitReason: acc.RateLimitReason,
			Entrypoint: ep, HasRefresh: acc.Credentials.RefreshToken != "",
			Proxy: proxyDisplay, Timezone: tzName, Language: geo.Language,
			Concurrency: acc.Concurrency,
			RateWindow5h: prune(acc.RateWindow5h), RateWindow7d: prune(acc.RateWindow7d),
			OutputStyle: acc.OutputStyle,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": rows})
}

// add handles account creation. Modes:
//   - {"mode":"session_key","session_key":"...","name":"...","proxy_url":"..."}
//   - {"mode":"manual","refresh_token":"...","access_token":"...","expires_at":"RFC3339",...}
func (a *Admin) add(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode         string `json:"mode"`
		Name         string `json:"name"`
		SessionKey   string `json:"session_key"`
		RefreshToken string `json:"refresh_token"`
		AccessToken  string `json:"access_token"`
		ExpiresAt    string `json:"expires_at"`
		Proxy        string `json:"proxy"`    // named proxy pool entry (preferred)
		ProxyURL     string `json:"proxy_url"` // raw URL fallback
		Entrypoint   string `json:"entrypoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	// Validate the named proxy reference.
	if req.Proxy != "" && !strings.Contains(req.Proxy, "://") {
		found := false
		for _, p := range a.cfg.Proxies {
			if p.Name == req.Proxy {
				found = true
				break
			}
		}
		if !found {
			writeErr(w, http.StatusBadRequest, "invalid_request_error", "unknown proxy pool name: "+req.Proxy)
			return
		}
	}
	proxy := req.ProxyURL
	if req.Proxy != "" {
		proxy = ""
	}
	if proxy == "" && req.Proxy == "" {
		proxy = a.cfg.DefaultProxyURL
	}
	entrypoint := req.Entrypoint
	if entrypoint == "" {
		entrypoint = a.cfg.Mimicry.DefaultEntrypoint
	}
	acc := &store.Account{Name: req.Name, Proxy: req.Proxy, ProxyURL: proxy}
	if acc.Name == "" {
		acc.Name = fmt.Sprintf("account-%d", time.Now().Unix())
	}
	// Effective egress URL (named pool resolves to its URL).
	egressURL := a.gw.geoFor(acc).ProxyURL

	switch req.Mode {
	case "session_key", "": // default mode
		if req.SessionKey == "" {
			writeErr(w, http.StatusBadRequest, "invalid_request_error", "session_key required")
			return
		}
		oc := oauth.New(egressURL)
		tr, err := oc.AuthorizeWithSessionKey(r.Context(), req.SessionKey)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "api_error", "sessionKey authorization failed: "+err.Error())
			return
		}
		acc.Credentials.AccessToken = tr.AccessToken
		acc.Credentials.RefreshToken = tr.RefreshToken
		if tr.ExpiresIn > 0 {
			acc.Credentials.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
		}
		if tr.Account != nil {
			acc.Extra.AccountUUID = tr.Account.UUID
			acc.Extra.Email = tr.Account.EmailAddress
		}
	case "manual":
		if req.RefreshToken == "" && req.AccessToken == "" {
			writeErr(w, http.StatusBadRequest, "invalid_request_error", "refresh_token or access_token required")
			return
		}
		acc.Credentials.AccessToken = req.AccessToken
		acc.Credentials.RefreshToken = req.RefreshToken
		acc.Credentials.ExpiresAt = req.ExpiresAt
	default:
		writeErr(w, http.StatusBadRequest, "invalid_request_error", "unknown mode: "+req.Mode)
		return
	}

	if err := a.st.Add(acc); err != nil {
		writeErr(w, http.StatusInternalServerError, "api_error", err.Error())
		return
	}
	// Provision the persistent identity so the entrypoint sticks.
	_ = a.st.Update(acc.ID, func(x *store.Account) {
		a.gw.provisionFingerprint(x, entrypoint)
	})
	created, _ := a.st.Get(acc.ID)
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": created.ID, "name": created.Name, "email": created.Extra.Email,
		"account_uuid": created.Extra.AccountUUID,
	})
}

func (a *Admin) remove(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	if err := a.st.Delete(id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

func (a *Admin) refresh(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	acc, err := a.st.Get(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found_error", err.Error())
		return
	}
	if acc.Credentials.RefreshToken == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request_error", "no refresh_token stored")
		return
	}
	proxy := acc.ProxyURL
	if proxy == "" {
		proxy = a.cfg.DefaultProxyURL
	}
	tr, err := oauth.New(proxy).Refresh(r.Context(), acc.Credentials.RefreshToken)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "api_error", "refresh failed: "+err.Error())
		return
	}
	_ = a.st.Update(id, func(x *store.Account) {
		x.Credentials.AccessToken = tr.AccessToken
		if tr.RefreshToken != "" {
			x.Credentials.RefreshToken = tr.RefreshToken
		}
		x.Credentials.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
		x.Status = "active"
		x.Error = ""
		x.RateLimitedUntil = nil
	})
	writeJSON(w, http.StatusOK, map[string]any{"refreshed": id})
}

func (a *Admin) oauthBegin(w http.ResponseWriter, r *http.Request) {
	oc := oauth.New("")
	res, err := oc.BeginBrowserFlow()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "api_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authorize_url": res.AuthorizeURL,
		"state":         res.State,
		"hint":          "open the URL, complete authorization, then POST the code (optionally 'code#state') to /admin/oauth/complete",
	})
}

func (a *Admin) oauthComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code     string `json:"code"`
		State    string `json:"state"`
		Name     string `json:"name"`
		Proxy    string `json:"proxy"`    // named proxy pool entry (preferred)
		ProxyURL string `json:"proxy_url"` // raw URL fallback
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	// Validate the named proxy reference.
	if req.Proxy != "" && !strings.Contains(req.Proxy, "://") {
		found := false
		for _, p := range a.cfg.Proxies {
			if p.Name == req.Proxy {
				found = true
				break
			}
		}
		if !found {
			writeErr(w, http.StatusBadRequest, "invalid_request_error", "unknown proxy pool name: "+req.Proxy)
			return
		}
	}
	// The code exchange carries the account's credentials: it must egress
	// through the same proxy the account will use afterwards.
	acc := &store.Account{Name: orDefault(req.Name, fmt.Sprintf("oauth-%d", time.Now().Unix()))}
	switch {
	case req.Proxy != "":
		acc.Proxy = req.Proxy
	case req.ProxyURL != "":
		acc.ProxyURL = req.ProxyURL
	default:
		acc.ProxyURL = a.cfg.DefaultProxyURL
	}
	oc := oauth.New(a.gw.geoFor(acc).ProxyURL)
	tr, err := oc.CompleteBrowserFlow(r.Context(), req.Code, req.State)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "api_error", "code exchange failed: "+err.Error())
		return
	}
	acc.Credentials = store.Credentials{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).UTC().Format(time.RFC3339),
	}
	if tr.Account != nil {
		acc.Extra.AccountUUID = tr.Account.UUID
		acc.Extra.Email = tr.Account.EmailAddress
	}
	if err := a.st.Add(acc); err != nil {
		writeErr(w, http.StatusInternalServerError, "api_error", err.Error())
		return
	}
	// Provision the persistent fingerprint identity (cli persona).
	_ = a.st.Update(acc.ID, func(x *store.Account) {
		a.gw.provisionFingerprint(x, "")
	})
	writeJSON(w, http.StatusCreated, map[string]any{"id": acc.ID, "name": acc.Name, "email": acc.Extra.Email, "proxy": acc.Proxy})
}

// usage returns per-account today/total aggregates:
// {account_id: {today:{...}, total:{reqs,errors,input,output,cache_write,cache_read}}}.
func (a *Admin) usage(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"usage": a.gw.UsageAggregates()})
}

// usageLogs returns newest-first per-request records.
// Query: ?account_id=&limit= (default 100, max 2000).
func (a *Admin) usageLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 100
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 {
		limit = v
	}
	accountID := int64(0)
	if v, err := strconv.ParseInt(q.Get("account_id"), 10, 64); err == nil && v > 0 {
		accountID = v
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": a.gw.UsageRecords(accountID, limit)})
}

// reauthorize replaces the credentials of an EXISTING account (sessionKey or
// OAuth code), keeping its identity: name, proxy binding, fingerprint,
// rate-limit windows and usage history all stay. This is the recovery path
// for accounts whose refresh token died (invalid_grant).
func (a *Admin) reauthorize(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	acc, err := a.st.Get(id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found_error", err.Error())
		return
	}
	var req struct {
		SessionKey string `json:"session_key"`
		Code       string `json:"code"`
		State      string `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	// The exchange must egress through the account's own proxy: same exit
	// the credentials will be used from afterwards.
	oc := oauth.New(a.gw.geoFor(acc).ProxyURL)
	var tr *oauth.TokenResponse
	switch {
	case req.SessionKey != "":
		tr, err = oc.AuthorizeWithSessionKey(r.Context(), req.SessionKey)
	case req.Code != "":
		tr, err = oc.CompleteBrowserFlow(r.Context(), req.Code, req.State)
	default:
		writeErr(w, http.StatusBadRequest, "invalid_request_error", "session_key or code required")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadGateway, "api_error", "re-authorization failed: "+err.Error())
		return
	}
	_ = a.st.Update(id, func(x *store.Account) {
		x.Credentials.AccessToken = tr.AccessToken
		if tr.RefreshToken != "" {
			x.Credentials.RefreshToken = tr.RefreshToken
		}
		if tr.ExpiresIn > 0 {
			x.Credentials.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).UTC().Format(time.RFC3339)
		} else {
			x.Credentials.ExpiresAt = time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339)
		}
		if tr.Account != nil {
			if tr.Account.UUID != "" {
				x.Extra.AccountUUID = tr.Account.UUID
			}
			if x.Extra.Email == "" && tr.Account.EmailAddress != "" {
				x.Extra.Email = tr.Account.EmailAddress
			}
		}
		// Bring the account back to life: clear the auth error and cooldown.
		x.Status = "active"
		x.Error = ""
		x.RateLimitedUntil = nil
		x.RateLimitReason = ""
	})
	slog.Info("account_reauthorized", "account_id", id, "account", acc.Name)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": id, "name": acc.Name, "reauthorized": true,
		"email": acc.Extra.Email, "expires_at": time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).UTC().Format(time.RFC3339),
	})
}

// putSettings updates runtime settings (currently output_style) in memory
// and, when the config path is known, atomically back into config.json.
func (a *Admin) putSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OutputStyle *string `json:"output_style"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	if req.OutputStyle != nil {
		v := strings.ToLower(strings.TrimSpace(*req.OutputStyle))
		if v == "default" {
			v = ""
		}
		if !mimicry.ValidStyleKey(v) {
			writeErr(w, http.StatusBadRequest, "invalid_request_error",
				`unknown output_style: use "", "concise" or "proactive"`)
			return
		}
		a.settingsMu.Lock()
		a.cfg.Mimicry.OutputStyle = v
		a.settingsMu.Unlock()
		if a.cfgPath != "" {
			if err := updateConfigFile(a.cfgPath, "output_style", v); err != nil {
				slog.Warn("settings_persist_failed", "error", err.Error())
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"output_style": a.cfg.Mimicry.OutputStyle})
}

// updateConfigFile rewrites one JSON key in the config file atomically.
func updateConfigFile(path, key, value string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}
	mimic, _ := doc["mimicry"].(map[string]any)
	if mimic == nil {
		mimicry := map[string]any{}
		doc["mimicry"] = mimicry
		mimic = mimicry
	}
	if value == "" {
		delete(mimic, key)
	} else {
		mimic[key] = value
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func pathID(r *http.Request) (int64, error) {
	// Prefer the ServeMux pattern value: the trailing-segment fallback below
	// misparses sub-actions like /admin/accounts/{id}/refresh (last segment
	// is "refresh", not the id).
	if v := r.PathValue("id"); v != "" {
		var id int64
		if _, err := fmt.Sscanf(v, "%d", &id); err != nil || id <= 0 {
			return 0, fmt.Errorf("invalid account id")
		}
		return id, nil
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) == 0 {
		return 0, fmt.Errorf("missing id")
	}
	var id int64
	if _, err := fmt.Sscanf(parts[len(parts)-1], "%d", &id); err != nil || id <= 0 {
		return 0, fmt.Errorf("invalid account id")
	}
	return id, nil
}
