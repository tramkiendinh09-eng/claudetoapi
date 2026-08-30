// Package telemetry reproduces the CLI's first-party background traffic so a
// gateway account shows the same telemetry footprint as a real client.
//
// All field shapes come from a REAL captured request body (single -p session,
// 63 events) rather than payload inference:
//   analysis/claude-code/event_logging_ground_truth.json
//   analysis/claude-code/event_logging_protocol.md
//
// Envelope per event (ground-truth verified):
//   event_name, client_timestamp, model (with [1m] marker when 1m context),
//   session_id, user_type:"external", betas (comma-joined session betas),
//   env{21 keys}, entrypoint, is_interactive, client_type,
//   process (base64 JSON: uptime/rss/heap…/cpuUsage), additional_metadata
//   (base64 JSON event payload), event_id (uuid), device_id (64hex).
//
// Transport: POST https://api.anthropic.com/api/event_logging/v2/batch
// {events:[...]}, Bearer + x-service-name: claude-code + CLI UA.
// Flush: 10s schedule delay, max 400 per batch (tengu_1p_event_batch_config
// defaults: scheduledDelayMillis=10000, maxExportBatchSize=400).
//
// Flag eval leg (GrowthBook remote-eval, from payload):
//   POST /api/eval-authed/sdk-zAZezfDKGoZuXXKe → fallback /api/eval/…
//   refresh 360min ±10% jitter.
package telemetry

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// Protocol constants (ground-truth + payload verified).
const (
	DefaultHost     = "https://api.anthropic.com"
	ClientSDKKey    = "sdk-zAZezfDKGoZuXXKe"
	ServiceName     = "claude-code"
	EventsBatchPath = "/api/event_logging/v2/batch"
	EvalPath        = "/api/eval/" + ClientSDKKey
	maxBatchSize    = 400
	flushInterval   = 10 * time.Second
)

// SessionBetas mirrors the full session beta list from the capture (note:
// broader than the per-request anthropic-beta header set).
const SessionBetas = "claude-code-20250219,context-1m-2025-08-07,interleaved-thinking-2025-05-14,thinking-token-count-2026-05-13,context-management-2025-06-27,prompt-caching-scope-2026-01-05,mid-conversation-system-2026-04-07"

// DeviceIdentity carries the stable per-account identity for telemetry.
type DeviceIdentity struct {
	ClientID    string // 64-hex device id → device_id
	AccountUUID string
	OrgUUID     string
	CLIVersion  string
	UserAgent   string
	Entrypoint  string // cli / sdk-cli / claude-vscode
	Env         EnvFingerprint
}

// EnvFingerprint is the 21-key environment object the CLI attaches to every
// event (ground truth). It must stay consistent with the profile's
// X-Stainless headers (OS/arch/runtime) — a win32 env under Linux headers
// would be a contradiction.
type EnvFingerprint struct {
	Platform    string // win32 | linux | darwin
	Arch        string // x64 | arm64
	NodeVersion string // matches X-Stainless-Runtime-Version
	Terminal    string
	Shell       string
	BuildTime   string // the CLI build timestamp (fixed per release)
	IsBun       bool
}

// BuildEnv assembles the 21-key env object in capture order.
func (e EnvFingerprint) BuildEnv(cliVersion string) map[string]any {
	deployment := "unknown-" + e.Platform
	return map[string]any{
		"platform":               e.Platform,
		"node_version":           e.NodeVersion,
		"terminal":               e.Terminal,
		"package_managers":       "npm",
		"runtimes":               "node",
		"is_running_with_bun":    e.IsBun,
		"is_ci":                  false,
		"is_claubbit":            false,
		"is_github_action":       false,
		"is_claude_code_action":  false,
		"is_claude_ai_auth":      false,
		"version":                cliVersion,
		"arch":                   e.Arch,
		"is_claude_code_remote":  false,
		"deployment_environment": deployment,
		"is_conductor":           false,
		"version_base":           cliVersion,
		"build_time":             e.BuildTime,
		"is_local_agent_mode":    false,
		"platform_raw":           e.Platform,
		"shell":                  e.Shell,
	}
}

// DefaultEnv derives the env from the profile's Stainless identity:
// Linux/x64, matching @anthropic-ai/claude-code-linux-x64 on glibc VPS.
func DefaultEnv(nodeVersion, buildTime string) EnvFingerprint {
	if nodeVersion == "" {
		nodeVersion = "v24.3.0"
	}
	if buildTime == "" {
		buildTime = "2026-08-26T05:55:19Z" // 2.1.247 native BUILD_TIME
	}
	return EnvFingerprint{
		Platform:    "linux",
		Arch:        "x64",
		NodeVersion: nodeVersion,
		Terminal:    "xterm-256color",
		Shell:       "bash",
		BuildTime:   buildTime,
		IsBun:       false,
	}
}

// processMetrics fakes a plausible Node.js process snapshot. Uptime tracks
// runner age; memory figures random-walk inside real capture bounds
// (rss 280-420MB, heap 30-90MB as in the sample).
type processMetrics struct {
	startedAt time.Time
	rss       int64
	heapTotal int64
	heapUsed  int64
	external  int64
	cpuUser   int64
	cpuSystem int64
}

func newProcessMetrics() *processMetrics {
	return &processMetrics{
		startedAt: time.Now(),
		rss:       290_000_000 + rand.Int63n(60_000_000),
		heapTotal: 36_000_000 + rand.Int63n(10_000_000),
		heapUsed:  52_000_000 + rand.Int63n(15_000_000),
		external:  20_000_000 + rand.Int63n(8_000_000),
		cpuUser:   200_000 + rand.Int63n(300_000),
		cpuSystem: 150_000 + rand.Int63n(200_000),
	}
}

func (p *processMetrics) snapshot() map[string]any {
	uptime := time.Since(p.startedAt).Seconds()
	p.cpuUser += rand.Int63n(80_000)
	p.cpuSystem += rand.Int63n(40_000)
	return map[string]any{
		"uptime":            uptime,
		"rss":               p.rss + rand.Int63n(4_000_000),
		"heapTotal":         p.heapTotal,
		"heapUsed":          p.heapUsed + rand.Int63n(2_000_000),
		"external":          p.external,
		"arrayBuffers":      30_000 + rand.Int63n(10_000),
		"constrainedMemory": 16_870_006_784 + rand.Int63n(1024),
		"cpuUsage": map[string]any{
			"user":   p.cpuUser,
			"system": p.cpuSystem,
		},
	}
}

// Transport abstracts the HTTP POST (gateway injects the ordered,
// fingerprinted transport so telemetry shares the real egress path).
type Transport interface {
	Post(ctx context.Context, url string, headers map[string]string, body []byte) (int, []byte, error)
}

// HTTPTransport adapts an *http.Client to Transport.
type HTTPTransport struct {
	Client *http.Client
}

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

// Telemetry runs the background loops for one account.
type Telemetry struct {
	ID       DeviceIdentity
	ProxyURL string
	HTTP     Transport

	mu           sync.Mutex
	queue        []map[string]any
	currentToken string
	proc         *processMetrics
	bootSession  string
	// session template: last conversation seen (model/betas/session_id).
	lastModel     string
	lastBetas     string
	lastSessionID string

	stop    chan struct{}
	stopped sync.Once
}

// New builds a telemetry runner.
func New(id DeviceIdentity, proxyURL string, transport Transport) *Telemetry {
	return &Telemetry{
		ID:          id,
		ProxyURL:    proxyURL,
		HTTP:        transport,
		proc:        newProcessMetrics(),
		bootSession: randomUUID(),
		stop:        make(chan struct{}),
	}
}

// Start launches the flush loop and the eval refresh loop.
func (t *Telemetry) Start() {
	go t.flushLoop()
	go t.evalLoop()
}

// Stop terminates the loops and flushes what is queued.
func (t *Telemetry) Stop() {
	t.stopped.Do(func() { close(t.stop) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = t.Flush(ctx)
}

// b64 encodes a JSON object the way the CLI does (base64(JSON)).
func b64(v any) string {
	raw, _ := json.Marshal(v)
	return base64.StdEncoding.EncodeToString(raw)
}

// envelope assembles the full event wrapper (ground-truth field order).
func (t *Telemetry) envelope(name string, metadata map[string]any) map[string]any {
	t.mu.Lock()
	model := t.lastModel
	betas := t.lastBetas
	sessionID := t.lastSessionID
	t.mu.Unlock()
	if betas == "" {
		betas = SessionBetas
	}
	if sessionID == "" {
		sessionID = t.bootSession
	}
	if model == "" {
		model = "claude-opus-5[1m]"
	}
	entrypoint := t.ID.Entrypoint
	if entrypoint == "" {
		entrypoint = "cli"
	}
	clientType := entrypoint
	if entrypoint == "cli" {
		clientType = "sdk-cli" // capture: cli entry runs as sdk-cli client type
	}
	return map[string]any{
		"event_name":          name,
		"client_timestamp":    time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"model":               model,
		"session_id":          sessionID,
		"user_type":           "external",
		"betas":               betas,
		"env":                 t.ID.Env.BuildEnv(t.ID.CLIVersion),
		"entrypoint":          entrypoint,
		"is_interactive":      false,
		"client_type":         clientType,
		"process":             b64(t.proc.snapshot()),
		"additional_metadata": b64(metadata),
		"event_id":            randomUUID(),
		"device_id":           t.ID.ClientID,
	}
}

// Emit queues a first-party event wrapped in the ground-truth envelope.
func (t *Telemetry) Emit(name string, metadata map[string]any) {
	if metadata == nil {
		metadata = map[string]any{}
	}
	ev := map[string]any{
		"event_type": "ClaudeCodeInternalEvent",
		"event_data": t.envelope(name, metadata),
	}
	t.mu.Lock()
	t.queue = append(t.queue, ev)
	t.mu.Unlock()
}

// NoteSession tells the runner which conversation is active, so later events
// carry the right session_id/model/betas.
func (t *Telemetry) NoteSession(sessionID, model, betas string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastSessionID = sessionID
	t.lastModel = model
	if betas != "" {
		t.lastBetas = betas
	}
}

// SetToken hands a fresh access token to the runner.
func (t *Telemetry) SetToken(token string) {
	t.mu.Lock()
	t.currentToken = token
	t.mu.Unlock()
}

// ---- startup sequence (fires once per runner = per CLI-process analog) ----

// BootSequence emits the startup event stream a real CLI produces at launch
// (ground truth: started/init first, then feature_ok ×20, skill_loaded ×16,
// cli_flags, then misc init events).
func (t *Telemetry) BootSequence() {
	t.Emit("tengu_started", map[string]any{
		"worktree_flag": false, "tmux_flag": false, "in_tmux_worktree": false,
	})
	t.Emit("tengu_cli_flags", map[string]any{"flag_count": 0, "flags": ""})
	t.Emit("tengu_init", map[string]any{
		"entrypoint": t.ID.Entrypoint, "bootstrap_entry": "cli",
		"hasInitialPrompt": false, "hasStdin": true, "verbose": false,
		"debug": false, "debugToStderr": false, "print": false,
		"outputFormat": "text", "inputFormat": "text",
		"numAllowedTools": 0, "numDisallowedTools": 0, "mcpClientCount": 0,
		"has_mcp_stdio": false, "has_mcp_managed": false,
		"has_mcp_localhost": false, "has_mcp_private_network": false,
	})
	// A handful of feature_ok (flag eval success) — full burst is 20+; we
	// replay the plausible core set the CLI evaluates first.
	for _, flag := range []string{
		"plugin_load_all", "tengu_gb_eval_authed_enable",
		"tengu_lantern_spool", "tengu_cedar_lattice", "tengu_tool_pear",
	} {
		t.Emit("tengu_feature_ok", map[string]any{"feature_name": flag})
	}
	// Bundled skills load at boot (16 in the capture; emit the canonical set).
	for _, skill := range []string{"docx", "pdf", "pptx", "xlsx", "frontend-design"} {
		t.Emit("tengu_skill_loaded", map[string]any{
			"skill_source": "bundled", "skill_loaded_from": "bundled",
			"skill_kind": "workflow", "model_invocable": false,
			"is_conditional": false, "skill_name": skill,
		})
	}
}

// ---- conversation events ----

// QueryPrompt emits tengu_input_prompt — the real per-turn marker which
// carries the conversation's cc_prompt_id (the billing chain field).
func (t *Telemetry) QueryPrompt(ccPromptID string, promptIndex, promptLen int) {
	t.Emit("tengu_input_prompt", map[string]any{
		"cc_prompt_id":  ccPromptID,
		"is_negative":   false,
		"is_keep_going": false,
		"is_wakeup":     false,
		"prompt_index":  promptIndex,
		"prompt_length": promptLen,
		"prompt_source": "sdk",
	})
}

// QueryDone emits the per-request completion event the CLI records
// (payload fn bKf: tengu_api_query with model/token/beta context).
func (t *Telemetry) QueryDone(model string, stream bool, inputTokens, outputTokens int64, thinking bool) {
	thinkingType := "disabled"
	if thinking {
		thinkingType = "enabled"
	}
	t.Emit("tengu_api_query", map[string]any{
		"model":           model,
		"stream":          stream,
		"input_tokens":    inputTokens,
		"output_tokens":   outputTokens,
		"thinkingType":    thinkingType,
		"provider":        "firstParty",
		"permission_mode": "default",
	})
}

// ---- transport ----

// Flush ships queued events in batches of maxBatchSize (ground truth: 400).
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
			t.mu.Lock()
			t.queue = append(pending[i:], t.queue...)
			t.mu.Unlock()
			break
		}
	}
	return firstErr
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

// fetchEval performs one remote-eval pull (flag config), falling back to the
// unauthenticated path on auth failure — exactly the payload's logic.
func (t *Telemetry) fetchEval(ctx context.Context) {
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
	t.mu.Lock()
	token := t.currentToken
	t.mu.Unlock()
	if token != "" {
		status, _, err := t.HTTP.Post(ctx, DefaultHost+"/api/eval-authed/"+ClientSDKKey, map[string]string{
			"Content-Type":  "application/json",
			"User-Agent":    t.ID.UserAgent,
			"Authorization": "Bearer " + token,
		}, body)
		if err == nil && status < 400 {
			slog.Debug("telemetry_eval_authed_ok", "status", status)
			return
		}
		slog.Debug("telemetry_eval_authed_fallback", "status", status, "error", err)
	}
	status, _, err := t.HTTP.Post(ctx, DefaultHost+EvalPath, map[string]string{
		"Content-Type": "application/json",
		"User-Agent":   t.ID.UserAgent,
	}, body)
	slog.Debug("telemetry_eval", "status", status, "error", err)
}

// evalLoop mirrors the refresh cadence: 360min default ±10% jitter.
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
			t.fetchEval(ctx)
			cancel()
		}
	}
}

// flushLoop ships queued events on the CLI's 10s schedule delay.
func (t *Telemetry) flushLoop() {
	ticker := time.NewTicker(flushInterval)
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

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}

func randomUUID() string {
	b := make([]byte, 16)
	_, _ = cryptorand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
