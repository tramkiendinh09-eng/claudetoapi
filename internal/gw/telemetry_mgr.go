package gw

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"claudetoapi/internal/store"
	"claudetoapi/internal/telemetry"
)

// TelemetryManager owns one telemetry runner per account. Runners ride the
// same ordered transport pool as message traffic (per-account egress) and
// stop when the account leaves the pool.
type TelemetryManager struct {
	gw *Gateway

	mu      sync.Mutex
	runners map[int64]*telemetry.Telemetry
}

// NewTelemetryManager builds the per-account telemetry runner manager.
func NewTelemetryManager(g *Gateway) *TelemetryManager {
	return &TelemetryManager{gw: g, runners: map[int64]*telemetry.Telemetry{}}
}

// Enabled reports the config switch.
func (m *TelemetryManager) Enabled() bool {
	return m.gw.cfg.Mimicry.TelemetryBypass
}

// EnsureStarted (re)creates the runner for an account: startup eval pull,
// boot event sequence, token handoff. Safe to call on every request.
func (m *TelemetryManager) EnsureStarted(acc *store.Account, accessToken string) {
	if !m.Enabled() || acc == nil || acc.ID <= 0 {
		return
	}
	m.mu.Lock()
	runner, ok := m.runners[acc.ID]
	m.mu.Unlock()
	if ok {
		runner.SetToken(accessToken)
		return
	}

	fp, prof := m.gw.resolveFingerprint(acc, "")
	geo := m.gw.geoFor(acc)
	ua := orDefault(fp.UserAgent, prof.UserAgent)
	runner = telemetry.New(telemetry.DeviceIdentity{
		ClientID:    fp.ClientID,
		AccountUUID: acc.Extra.AccountUUID,
		CLIVersion:  prof.CLIVersion,
		UserAgent:   ua,
		Entrypoint:  fp.Entrypoint,
		Env:         telemetry.DefaultEnv(prof.Stainless["X-Stainless-Runtime-Version"], ""),
	}, geo.ProxyURL, &telemetry.HTTPTransport{
		Client: &http.Client{Transport: SharedOrderedTransport(geo.ProxyURL), Timeout: 15 * time.Second},
	})
	runner.SetToken(accessToken)

	m.mu.Lock()
	if existing, ok := m.runners[acc.ID]; ok {
		// Another goroutine won the race.
		m.mu.Unlock()
		existing.SetToken(accessToken)
		return
	}
	m.runners[acc.ID] = runner
	m.mu.Unlock()

	runner.Start()

	// Boot: the real CLI pulls flag config once at startup (init), then emits
	// the startup event burst (ground truth: started/init/feature_ok/…).
	runner.BootSequence()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_ = runner.Flush(ctx)
	cancel()
	slog.Info("telemetry_runner_started", "account_id", acc.ID)
}

// NotifyConversationStart emits the per-turn prompt marker with the chain's
// cc_prompt_id (ties telemetry to the billing chain, as in the capture).
func (m *TelemetryManager) NotifyConversationStart(acc *store.Account, sessionID, model, betas, ccPromptID string, promptLen int) {
	if !m.Enabled() {
		return
	}
	m.mu.Lock()
	runner := m.runners[acc.ID]
	m.mu.Unlock()
	if runner == nil {
		return
	}
	runner.NoteSession(sessionID, model, betas)
	runner.QueryPrompt(ccPromptID, 1, promptLen)
}

// NotifyQuery emits the per-request usage event the real CLI records.
func (m *TelemetryManager) NotifyQuery(acc *store.Account, model string, stream bool, inputTokens, outputTokens int64, thinking bool) {
	if !m.Enabled() {
		return
	}
	m.mu.Lock()
	runner := m.runners[acc.ID]
	m.mu.Unlock()
	if runner == nil {
		return
	}
	runner.QueryDone(model, stream, inputTokens, outputTokens, thinking)
}

// StopAll shuts down every runner (flushes pending events).
func (m *TelemetryManager) StopAll() {
	m.mu.Lock()
	runners := make([]*telemetry.Telemetry, 0, len(m.runners))
	for id, r := range m.runners {
		runners = append(runners, r)
		delete(m.runners, id)
	}
	m.mu.Unlock()
	for _, r := range runners {
		r.Stop()
	}
}

// Stats returns runner count for the admin console.
func (m *TelemetryManager) Stats() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.runners)
}
