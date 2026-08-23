package telemetry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"
)

// stubTransport records POSTs.
type stubTransport struct {
	mu       sync.Mutex
	requests []stubRequest
}

type stubRequest struct {
	URL     string
	Headers map[string]string
	Body    []byte
}

func (s *stubTransport) Post(ctx context.Context, url string, headers map[string]string, body []byte) (int, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, stubRequest{URL: url, Headers: headers, Body: body})
	return 200, []byte(`{}`), nil
}

func testIdentity() DeviceIdentity {
	return DeviceIdentity{
		ClientID:    "df7f00c8a71a7cd61ce9096069cf776de8d48dbf425007f6d1f4f45f5533f452",
		AccountUUID: "uuid-1",
		OrgUUID:     "org-1",
		CLIVersion:  "2.1.241",
		UserAgent:   "claude-cli/2.1.241 (external, cli)",
		Entrypoint:  "cli",
		Env:         DefaultEnv("v24.3.0", "2026-08-22T22:46:48Z"),
	}
}

// TestEnvelopeMatchesGroundTruth asserts every envelope field against the
// captured 2.1.241 event shape (event_logging_ground_truth.json).
func TestEnvelopeMatchesGroundTruth(t *testing.T) {
	tr := &stubTransport{}
	tele := New(testIdentity(), "", tr)
	tele.SetToken("tok123")
	tele.NoteSession("38223b36-f8cb-42f6-bb57-6057666f341a", "claude-opus-5[1m]", "")
	tele.QueryPrompt("a14f546e-59a7-412e-8faf-ee5dc9deeb09", 1, 12)

	if err := tele.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.requests) != 1 {
		t.Fatalf("expected 1 batch request, got %d", len(tr.requests))
	}
	req := tr.requests[0]
	if req.URL != DefaultHost+"/api/event_logging/v2/batch" {
		t.Fatalf("wrong endpoint: %s", req.URL)
	}
	if req.Headers["Authorization"] != "Bearer tok123" {
		t.Fatal("auth header missing")
	}
	if req.Headers["x-service-name"] != "claude-code" {
		t.Fatal("x-service-name missing")
	}

	var payload struct {
		Events []struct {
			EventType string         `json:"event_type"`
			EventData map[string]any `json:"event_data"`
		} `json:"events"`
	}
	if err := json.Unmarshal(req.Body, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(payload.Events))
	}
	d := payload.Events[0].EventData

	// Envelope fields (ground truth).
	if d["event_name"] != "tengu_input_prompt" {
		t.Fatalf("event_name: %v", d["event_name"])
	}
	if d["client_timestamp"] == nil {
		t.Fatal("client_timestamp missing")
	}
	if d["model"] != "claude-opus-5[1m]" {
		t.Fatalf("model: %v", d["model"])
	}
	if d["session_id"] != "38223b36-f8cb-42f6-bb57-6057666f341a" {
		t.Fatalf("session_id: %v", d["session_id"])
	}
	if d["user_type"] != "external" {
		t.Fatalf("user_type: %v", d["user_type"])
	}
	if d["betas"] != SessionBetas {
		t.Fatalf("betas: %v", d["betas"])
	}
	if d["entrypoint"] != "cli" || d["client_type"] != "sdk-cli" {
		t.Fatalf("entrypoint/client_type: %v/%v", d["entrypoint"], d["client_type"])
	}
	if d["is_interactive"] != false {
		t.Fatalf("is_interactive: %v", d["is_interactive"])
	}
	if d["device_id"] != "df7f00c8a71a7cd61ce9096069cf776de8d48dbf425007f6d1f4f45f5533f452" {
		t.Fatalf("device_id: %v", d["device_id"])
	}
	if d["event_id"] == nil {
		t.Fatal("event_id missing")
	}

	// env: all 21 keys present.
	env, ok := d["env"].(map[string]any)
	if !ok {
		t.Fatal("env missing")
	}
	wantEnvKeys := []string{
		"platform", "node_version", "terminal", "package_managers", "runtimes",
		"is_running_with_bun", "is_ci", "is_claubbit", "is_github_action",
		"is_claude_code_action", "is_claude_ai_auth", "version", "arch",
		"is_claude_code_remote", "deployment_environment", "is_conductor",
		"version_base", "build_time", "is_local_agent_mode", "platform_raw", "shell",
	}
	for _, k := range wantEnvKeys {
		if _, ok := env[k]; !ok {
			t.Fatalf("env missing key %q", k)
		}
	}
	if env["platform"] != "linux" || env["arch"] != "arm64" || env["version"] != "2.1.241" {
		t.Fatalf("env mismatch: %v/%v/%v", env["platform"], env["arch"], env["version"])
	}

	// process: base64 JSON with the capture schema.
	procRaw, ok := d["process"].(string)
	if !ok {
		t.Fatal("process missing")
	}
	procBytes, err := base64.StdEncoding.DecodeString(procRaw)
	if err != nil {
		t.Fatal("process not base64")
	}
	var proc map[string]any
	if err := json.Unmarshal(procBytes, &proc); err != nil {
		t.Fatal("process not JSON")
	}
	for _, k := range []string{"uptime", "rss", "heapTotal", "heapUsed", "external", "arrayBuffers", "constrainedMemory", "cpuUsage"} {
		if _, ok := proc[k]; !ok {
			t.Fatalf("process missing key %q", k)
		}
	}

	// additional_metadata: base64 JSON with the event payload.
	amRaw, ok := d["additional_metadata"].(string)
	if !ok {
		t.Fatal("additional_metadata missing")
	}
	amBytes, err := base64.StdEncoding.DecodeString(amRaw)
	if err != nil {
		t.Fatal("additional_metadata not base64")
	}
	var am map[string]any
	if err := json.Unmarshal(amBytes, &am); err != nil {
		t.Fatal("additional_metadata not JSON")
	}
	if am["cc_prompt_id"] != "a14f546e-59a7-412e-8faf-ee5dc9deeb09" {
		t.Fatalf("cc_prompt_id: %v", am["cc_prompt_id"])
	}
	if am["prompt_length"] != float64(12) {
		t.Fatalf("prompt_length: %v", am["prompt_length"])
	}
}

// TestBootSequenceEmitsStartupEvents verifies the launch burst.
func TestBootSequenceEmitsStartupEvents(t *testing.T) {
	tr := &stubTransport{}
	tele := New(testIdentity(), "", tr)
	tele.BootSequence()
	if err := tele.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.requests) != 1 {
		t.Fatalf("expected 1 batch, got %d", len(tr.requests))
	}
	var payload struct {
		Events []struct {
			EventData map[string]any `json:"event_data"`
		} `json:"events"`
	}
	if err := json.Unmarshal(tr.requests[0].Body, &payload); err != nil {
		t.Fatal(err)
	}
	names := map[string]int{}
	for _, e := range payload.Events {
		names[e.EventData["event_name"].(string)]++
	}
	for _, required := range []string{"tengu_started", "tengu_init", "tengu_cli_flags", "tengu_feature_ok", "tengu_skill_loaded"} {
		if names[required] == 0 {
			t.Fatalf("startup burst missing %s", required)
		}
	}
}

func TestFlushEmptyIsNoop(t *testing.T) {
	tr := &stubTransport{}
	tele := New(DeviceIdentity{}, "", tr)
	if err := tele.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(tr.requests) != 0 {
		t.Fatalf("no requests expected, got %d", len(tr.requests))
	}
}
