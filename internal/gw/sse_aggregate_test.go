package gw

import (
	"strings"
	"testing"
)

func TestCollectAnthropicSSETextAndUsage(t *testing.T) {
	src := strings.Join([]string{
		`event: message_start`,
		`data: {"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-5","content":[],"usage":{"input_tokens":11,"cache_read_input_tokens":200}}}`,
		``,
		`event: content_block_start`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hel"}}`,
		``,
		`event: content_block_delta`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"lo"}}`,
		``,
		`event: content_block_stop`,
		`data: {"type":"content_block_stop","index":0}`,
		``,
		`event: message_delta`,
		`data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}}`,
		``,
		`event: message_stop`,
		`data: {"type":"message_stop"}`,
		``,
	}, "\n")
	raw, u, err := collectAnthropicSSE(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if u.input != 11 || u.cacheRead != 200 || u.output != 2 {
		t.Fatalf("usage %+v", u)
	}
	s := string(raw)
	if !strings.Contains(s, `"hello"`) || !strings.Contains(s, `"stop_reason":"end_turn"`) {
		t.Fatalf("aggregated body: %s", s)
	}
}

func TestCollectAnthropicSSEThinkingAndToolUse(t *testing.T) {
	src := strings.Join([]string{
		`data: {"type":"message_start","message":{"id":"msg_2","type":"message","role":"assistant","content":[]}}`,
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"plan"}}`,
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig"}}`,
		`data: {"type":"content_block_stop","index":0}`,
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"bash","input":{}}}`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"cmd\":"}}`,
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"ls\"}"}}`,
		`data: {"type":"content_block_stop","index":1}`,
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":9}}`,
	}, "\n")
	raw, _, err := collectAnthropicSSE(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, `"thinking":"plan"`) || !strings.Contains(s, `"signature":"sig"`) {
		t.Fatalf("missing thinking: %s", s)
	}
	if !strings.Contains(s, `"name":"bash"`) || !strings.Contains(s, `"cmd":"ls"`) {
		t.Fatalf("missing tool input: %s", s)
	}
}

func TestCollectAnthropicSSEErrorEvent(t *testing.T) {
	src := `data: {"type":"error","error":{"type":"overloaded_error","message":"busy"}}` + "\n"
	if _, _, err := collectAnthropicSSE(strings.NewReader(src)); err == nil {
		t.Fatal("expected error event to fail the aggregate")
	}
}
