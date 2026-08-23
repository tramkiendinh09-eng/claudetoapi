package telemetry

import (
	"context"
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

func TestEmitAndFlushEventShape(t *testing.T) {
	tr := &stubTransport{}
	tele := New(DeviceIdentity{
		ClientID:    "abcd",
		AccountUUID: "uuid-1",
		CLIVersion: "2.1.241",
		UserAgent:   "claude-cli/2.1.241 (external, cli)",
	}, "", tr)
	tele.SetToken("tok123")
	tele.Emit("tengu_api_query", map[string]any{"model": "claude-sonnet-4-5"})

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
		t.Fatalf("auth header missing: %v", req.Headers)
	}
	if req.Headers["x-service-name"] != "claude-code" {
		t.Fatalf("x-service-name missing: %v", req.Headers)
	}
	var payload struct {
		Events []struct {
			EventType string `json:"event_type"`
			EventData struct {
				EventName    string         `json:"event_name"`
				EventID      string         `json:"event_id"`
				UserID       string         `json:"user_id"`
				CoreMetadata map[string]any `json:"core_metadata"`
				UserMetadata struct {
					AccountUUID string `json:"account_uuid"`
				} `json:"user_metadata"`
				Metadata map[string]any `json:"event_metadata"`
			} `json:"event_data"`
		} `json:"events"`
	}
	if err := json.Unmarshal(req.Body, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if len(payload.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(payload.Events))
	}
	ev := payload.Events[0]
	if ev.EventType != "ClaudeCodeInternalEvent" {
		t.Fatalf("wrong event_type: %s", ev.EventType)
	}
	if ev.EventData.EventName != "tengu_api_query" {
		t.Fatalf("wrong event_name: %s", ev.EventData.EventName)
	}
	if ev.EventData.UserID != "abcd" {
		t.Fatalf("user_id must be device id: %s", ev.EventData.UserID)
	}
	if ev.EventData.UserMetadata.AccountUUID != "uuid-1" {
		t.Fatalf("account_uuid missing: %+v", ev.EventData.UserMetadata)
	}
	if ev.EventData.CoreMetadata["cli_version"] != "2.1.241" {
		t.Fatalf("core_metadata missing version: %+v", ev.EventData.CoreMetadata)
	}
	if ev.EventData.Metadata["model"] != "claude-sonnet-4-5" {
		t.Fatalf("event_metadata missing: %+v", ev.EventData.Metadata)
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
