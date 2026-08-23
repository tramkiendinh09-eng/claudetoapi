// Package oauth implements the Claude Code OAuth dance: the official CLI
// client id with PKCE, a browser-flow helper, a sessionKey-driven automatic
// flow, and refresh_token rotation.
package oauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Endpoints and client identity (identical to the official CLI).
const (
	ClientID    = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	AuthorizeURL = "https://claude.com/cai/oauth/authorize"
	TokenURL     = "https://platform.claude.com/v1/oauth/token"
	RedirectURI  = "https://platform.claude.com/oauth/code/callback"

	ScopeBrowser = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
)

// TokenResponse is the token endpoint payload.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Organization *struct {
		UUID string `json:"uuid"`
	} `json:"organization,omitempty"`
	Account *struct {
		UUID         string `json:"uuid"`
		EmailAddress string `json:"email_address"`
	} `json:"account,omitempty"`
}

// Client performs OAuth against claude.ai / platform.claude.com.
type Client struct {
	HTTP *http.Client
}

func New(proxyURL string) *Client {
	t := &http.Transport{Proxy: http.ProxyFromEnvironment}
	if proxyURL != "" {
		if u, err := url.Parse(proxyURL); err == nil {
			t.Proxy = http.ProxyURL(u)
		}
	}
	return &Client{HTTP: &http.Client{Timeout: 60 * time.Second, Transport: t}}
}

// ---- PKCE helpers ----

func randomB64URL(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func codeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// BeginResult describes a started browser authorization flow.
type BeginResult struct {
	AuthorizeURL string
	State        string
}

// pending tracks in-memory PKCE sessions for the browser flow.
var (
	pendingMu sync.Mutex
	pending   = map[string]string{} // state -> code_verifier
)

// BeginBrowserFlow builds the authorization URL the user should open. The
// redirect lands on platform.claude.com/oauth/code/callback; the user copies
// the "code" (and state) from the URL or page and posts it to CompleteBrowserFlow.
func (c *Client) BeginBrowserFlow() (*BeginResult, error) {
	verifier, err := randomB64URL(32)
	if err != nil {
		return nil, err
	}
	state, err := randomB64URL(32)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("code", "true")
	q.Set("client_id", ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", RedirectURI)
	q.Set("scope", strings.ReplaceAll(url.QueryEscape(ScopeBrowser), "%20", "+"))
	q.Set("code_challenge", codeChallenge(verifier))
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)

	pendingMu.Lock()
	pending[state] = verifier
	pendingMu.Unlock()

	return &BeginResult{
		AuthorizeURL: AuthorizeURL + "?" + q.Encode(),
		State:        state,
	}, nil
}

// CompleteBrowserFlow exchanges the authorization code for tokens.
// code may be "authCode" or "authCode#state"; state overrides the split.
func (c *Client) CompleteBrowserFlow(ctx context.Context, code, state string) (*TokenResponse, error) {
	authCode := code
	codeState := ""
	if i := strings.Index(code, "#"); i >= 0 {
		authCode, codeState = code[:i], code[i+1:]
	}
	if state == "" {
		state = codeState
	}
	pendingMu.Lock()
	verifier := pending[state]
	delete(pending, state)
	pendingMu.Unlock()
	if verifier == "" {
		return nil, fmt.Errorf("unknown or expired state (browser flow sessions expire on use)")
	}
	return c.exchange(ctx, authCode, verifier, state)
}

// ---- token endpoint ----

func (c *Client) exchange(ctx context.Context, code, verifier, state string) (*TokenResponse, error) {
	body := map[string]any{
		"code":          code,
		"grant_type":    "authorization_code",
		"client_id":     ClientID,
		"redirect_uri":  RedirectURI,
		"code_verifier": verifier,
	}
	if state != "" {
		body["state"] = state
	}
	return c.postToken(ctx, body)
}

// Refresh rotates tokens with the refresh_token grant.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	return c.postToken(ctx, map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     ClientID,
	})
}

func (c *Client) postToken(ctx context.Context, body map[string]any) (*TokenResponse, error) {
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, TokenURL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	// The official web frontend exchanges tokens via axios; mirror that UA.
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "axios/1.13.6")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint status %d: %s", resp.StatusCode, truncate(data, 300))
	}
	var tr TokenResponse
	if err := json.Unmarshal(data, &tr); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token response missing access_token")
	}
	return &tr, nil
}

// ---- sessionKey automatic flow ----

// AuthorizeWithSessionKey drives the full browser-less flow using a claude.ai
// sessionKey cookie: pick organization (prefer team), POST the org-scoped
// authorize endpoint as the web app would, then exchange the returned code.
func (c *Client) AuthorizeWithSessionKey(ctx context.Context, sessionKey string) (*TokenResponse, error) {
	orgUUID, err := c.organizationUUID(ctx, sessionKey)
	if err != nil {
		return nil, err
	}

	verifier, err := randomB64URL(32)
	if err != nil {
		return nil, err
	}
	state, err := randomB64URL(32)
	if err != nil {
		return nil, err
	}

	authURL := "https://claude.ai/v1/oauth/" + orgUUID + "/authorize"
	payload := map[string]any{
		"response_type":         "code",
		"client_id":             ClientID,
		"organization_uuid":     orgUUID,
		"redirect_uri":          RedirectURI,
		"scope":                 ScopeBrowser,
		"state":                 state,
		"code_challenge":        codeChallenge(verifier),
		"code_challenge_method": "S256",
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, authURL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.AddCookie(&http.Cookie{Name: "sessionKey", Value: sessionKey})
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Origin", "https://claude.ai")
	req.Header.Set("Referer", "https://claude.ai/new")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authorize request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authorize status %d: %s", resp.StatusCode, truncate(data, 300))
	}
	var out struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.RedirectURI == "" {
		return nil, fmt.Errorf("authorize response missing redirect_uri")
	}
	u, err := url.Parse(out.RedirectURI)
	if err != nil {
		return nil, fmt.Errorf("parse redirect_uri: %w", err)
	}
	authCode := u.Query().Get("code")
	respState := u.Query().Get("state")
	if authCode == "" {
		return nil, fmt.Errorf("redirect_uri carries no code")
	}
	return c.exchange(ctx, authCode, verifier, respState)
}

func (c *Client) organizationUUID(ctx context.Context, sessionKey string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://claude.ai/api/organizations", nil)
	if err != nil {
		return "", err
	}
	req.AddCookie(&http.Cookie{Name: "sessionKey", Value: sessionKey})
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("organizations request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("organizations status %d: %s", resp.StatusCode, truncate(data, 300))
	}
	var orgs []struct {
		UUID      string  `json:"uuid"`
		Name      string  `json:"name"`
		RavenType *string `json:"raven_type"`
	}
	if err := json.Unmarshal(data, &orgs); err != nil {
		return "", fmt.Errorf("decode organizations: %w", err)
	}
	if len(orgs) == 0 {
		return "", fmt.Errorf("no organizations found for sessionKey")
	}
	// Prefer team organizations, matching the CLI's account picker.
	for _, o := range orgs {
		if o.RavenType != nil && *o.RavenType == "team" {
			return o.UUID, nil
		}
	}
	return orgs[0].UUID, nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}
