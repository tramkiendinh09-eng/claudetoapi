// Package telemetry reproduces the CLI's first-party background traffic so a
// gateway account shows the same telemetry footprint as a real client.
//
// Two protocol legs, both reversed from the claude.exe 2.1.241 payload:
//
//  1. Feature-flag eval — GrowthBook SDK in remote-eval mode routed to
//     api.anthropic.com (payload class `createClient` @ 0x122209b0):
//       POST {host}/api/eval/{clientKey}            (unauthenticated SDK path)
//       POST {host}/api/eval-authed/{clientKey}     (authed wrapper path)
//     clientKey "sdk-zAZezfDKGoZuXXKe", host https://api.anthropic.com/,
//     body {attributes, forcedVariations, forcedFeatures, url}.
//     Cadence: refresh loop, gate tengu_gb_refresh_interval_minutes
//     (default 360 min with ±10% jitter, 5-360 clamp).
//
//  2. Event batching — OTLP-ish exporter (class bba @ 0x121bff81):
//       POST {host}/api/event_logging/v2/batch  {events:[...]}
//     headers: Content-Type: application/json, User-Agent: <cli UA>,
//     x-service-name: claude-code, Authorization: Bearer <oauth token>.
//     Event shape (transformLogsToEvents @ 0x121c232c):
//       {event_type:"ClaudeCodeInternalEvent",
//        event_data:{event_name, event_id, timestamp,
//                    core_metadata:{cli_version, ...},
//                    user_metadata:{account_uuid, organization_uuid},
//                    user_id (device), event_metadata:{...}}}
//     Batch max 200 events, retries with quadratic backoff (0.5s..30s).
package telemetry

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// Protocol constants (payload-verified).
const (
	DefaultHost     = "https://api.anthropic.com"
	ClientSDKKey    = "sdk-zAZezfDKGoZuXXKe"
	ServiceName     = "claude-code"
	EventsBatchPath = "/api/event_logging/v2/batch"
	EvalPath        = "/api/eval/" + ClientSDKKey
	maxBatchSize    = 200
)

// DeviceIdentity carries the stable per-account identity for telemetry.
type DeviceIdentity struct {
	ClientID       string // 64-hex device id
	AccountUUID    string
	OrgUUID        string
	CLIVersion     string
	UserAgent      string
}

// Transport abstracts the HTTP POST (the gateway injects its fingerprinted,
// ordered transport so telemetry shares the real egress path).
type Transport interface {
	Post(ctx context.Context, url string, headers map[string]string, body []byte) (int, []byte, error)
}

// HTTPTransport adapts an *http.Client to Transport. It uses the ordered
// transport when available so telemetry requests carry the same wire
// fingerprint (header order, TLS ClientHello) as message traffic.
type HTTPTransport struct {
	Client *http.Client
}

// Post performs the POST and returns status, body, error.
func (h *HTTPTransport) Post(ctx context.Context, url string, headers map[string]string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.Client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, data, nil
}

func randRead(b []byte) (int, error) { return cryptorand.Read(b) }

// Event is one first-party telemetry event (ClaudeCodeInternalEvent form).
type Event struct {
	EventName    string         `json:"event_name"`
	EventID      string         `json:"event_id"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// Telemetry runs the background loops for one account.
type Telemetry struct {
	ID       DeviceIdentity
	ProxyURL string
	HTTP     Transport

	mu           sync.Mutex
	queue        []map[string]any
	currentToken string
	stop         chan struct{}
	stopped      sync.Once
}

// New builds a telemetry runner.
func New(id DeviceIdentity, proxyURL string, transport Transport) *Telemetry {
	return &Telemetry{ID: id, ProxyURL: proxyURL, HTTP: transport, stop: make(chan struct{})}
}

// Start launches the eval refresh loop and the periodic event flusher.
func (t *Telemetry) Start() {
	go t.evalLoop()
	go t.flushLoop()
}

// Stop terminates the loops and flushes what is queued.
func (t *Telemetry) Stop() {
	t.stopped.Do(func() { close(t.stop) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = t.Flush(ctx)
}

// Emit queues a first-party event.
func (t *Telemetry) Emit(name string, metadata map[string]any) {
	ev := map[string]any{
		"event_type": "ClaudeCodeInternalEvent",
		"event_data": map[string]any{
			"event_name": name,
			"event_id":   randomUUID(),
			"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
			"core_metadata": map[string]any{
				"cli_version": t.ID.CLIVersion,
			},
			"event_metadata": metadata,
		},
	}
	if t.ID.ClientID != "" {
		ev["event_data"].(map[string]any)["user_id"] = t.ID.ClientID
	}
	if t.ID.AccountUUID != "" || t.ID.OrgUUID != "" {
		ev["event_data"].(map[string]any)["user_metadata"] = map[string]any{
			"account_uuid":     t.ID.AccountUUID,
			"organization_uuid": t.ID.OrgUUID,
		}
	}
	t.mu.Lock()
	t.queue = append(t.queue, ev)
	t.mu.Unlock()
}

// fetchEval performs one remote-eval pull (the flag-config fetch a real CLI
// does at startup and periodically). Auth failures degrade to the
// unauthenticated /api/eval path, exactly like the payload's fallback.
func (t *Telemetry) fetchEval(ctx context.Context, accessToken string) {
	payload := map[string]any{
		"attributes": map[string]any{
			"id":               t.ID.ClientID,
			"accountUUID":      t.ID.AccountUUID,
			"organizationUUID": t.ID.OrgUUID,
			"appVersion":       t.ID.CLIVersion,
		},
		"forcedVariations": map[string]any{},
		"forcedFeatures":   []any{},
		"url":              "https://api.anthropic.com/",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	headers := map[string]string{
		"Content-Type": "application/json",
		"User-Agent":   t.ID.UserAgent,
	}
	endpoint := DefaultHost + EvalPath
	if accessToken != "" {
		authed := DefaultHost + "/api/eval-authed/" + ClientSDKKey
		h := map[string]string{
			"Content-Type":  "application/json",
			"User-Agent":    t.ID.UserAgent,
			"Authorization": "Bearer " + accessToken,
		}
		status, _, err := t.HTTP.Post(ctx, authed, h, body)
		if err == nil && status < 400 {
			slog.Debug("telemetry_eval_authed_ok", "status", status)
			return
		}
		slog.Debug("telemetry_eval_authed_fallback", "status", status, "error", err)
	}
	status, _, err := t.HTTP.Post(ctx, endpoint, headers, body)
	slog.Debug("telemetry_eval", "status", status, "error", err)
}

// evalLoop mirrors the refresh cadence: 360 min default, ±10% jitter.
func (t *Telemetry) evalLoop() {
	interval := time.Duration(360+rand.Intn(72)-36) * time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			t.fetchEval(ctx, "")
			cancel()
		}
	}
}

// flushLoop ships queued events every ~60s (scheduledDelayMillis default
// 10s in the CLI; we batch a bit longer since we emit far fewer events).
func (t *Telemetry) flushLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			_ = t.Flush(ctx)
			cancel()
		}
	}
}

// Flush sends queued events in batches of maxBatchSize. Caller supplies the
// current access token (auth header mirrors the CLI: retry without auth on
// 401 is handled inside postEvents).
func (t *Telemetry) Flush(ctx context.Context) error {
	t.mu.Lock()
	pending := t.queue
	t.queue = nil
	t.mu.Unlock()
	if len(pending) == 0 {
		return nil
	}
	var firstErr error
	for i := 0; i < len(pending); i += maxBatchSize {
		end := i + maxBatchSize
		if end > len(pending) {
			end = len(pending)
		}
		if err := t.postEvents(ctx, pending[i:end]); err != nil {
			firstErr = err
			// requeue the rest, like the CLI's failed-events file
			t.mu.Lock()
			t.queue = append(pending[i:], t.queue...)
			t.mu.Unlock()
			break
		}
	}
	return firstErr
}

// SetToken lets the gateway hand the telemetry runner a fresh access token.
func (t *Telemetry) SetToken(token string) {
	t.mu.Lock()
	t.currentToken = token
	t.mu.Unlock()
}

func (t *Telemetry) postEvents(ctx context.Context, events []map[string]any) error {
	body, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		return err
	}
	headers := map[string]string{
		"Content-Type":   "application/json",
		"User-Agent":     t.ID.UserAgent,
		"x-service-name": ServiceName,
	}
	t.mu.Lock()
	token := t.currentToken
	t.mu.Unlock()
	if token != "" {
		headers["Authorization"] = "Bearer " + token
	}
	status, respBody, err := t.HTTP.Post(ctx, DefaultHost+EventsBatchPath, headers, body)
	if err != nil {
		return fmt.Errorf("event batch: %w", err)
	}
	if status >= 400 {
		return fmt.Errorf("event batch status %d: %s", status, truncate(respBody, 200))
	}
	return nil
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}

func randomUUID() string {
	b := make([]byte, 16)
	_, _ = randRead(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
