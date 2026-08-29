package gw

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"claudetoapi/internal/mimicry"
)

func isSSEResponse(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("content-type"))
	return strings.Contains(ct, "text/event-stream")
}

// collectAnthropicSSE folds a Messages SSE stream into a single Messages JSON
// body so a client that asked for stream=false still gets JSON, while the
// upstream request rides the streaming lane (the lane OAuth does not 429).
func collectAnthropicSSE(r io.Reader) ([]byte, usageAcc, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 16<<20)

	var msg map[string]any
	var content []any
	var u usageAcc

	applyUsage := func(raw any) {
		m, _ := raw.(map[string]any)
		if m == nil {
			return
		}
		if v, ok := anyToInt64(m["input_tokens"]); ok {
			u.input = v
		}
		if v, ok := anyToInt64(m["output_tokens"]); ok && v > u.output {
			u.output = v
		}
		if v, ok := anyToInt64(m["cache_creation_input_tokens"]); ok {
			u.cacheWrite = v
		}
		if v, ok := anyToInt64(m["cache_read_input_tokens"]); ok {
			u.cacheRead = v
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			continue
		}
		switch ev["type"] {
		case "error":
			return nil, u, fmt.Errorf("upstream sse error: %s", truncateStr(payload, 300))
		case "message_start":
			if m, ok := ev["message"].(map[string]any); ok {
				msg = m
				if c, ok := m["content"].([]any); ok {
					content = c
				} else {
					content = []any{}
				}
				applyUsage(m["usage"])
			}
		case "content_block_start":
			if blk, ok := ev["content_block"].(map[string]any); ok {
				content = append(content, blk)
			}
		case "content_block_delta":
			idx := anyToInt(ev["index"])
			if idx < 0 || idx >= len(content) {
				continue
			}
			blk, _ := content[idx].(map[string]any)
			if blk == nil {
				continue
			}
			delta, _ := ev["delta"].(map[string]any)
			if delta == nil {
				continue
			}
			switch delta["type"] {
			case "text_delta":
				blk["text"] = anyToString(blk["text"]) + anyToString(delta["text"])
			case "thinking_delta":
				blk["thinking"] = anyToString(blk["thinking"]) + anyToString(delta["thinking"])
			case "signature_delta":
				blk["signature"] = anyToString(blk["signature"]) + anyToString(delta["signature"])
			case "input_json_delta":
				blk["_partial"] = anyToString(blk["_partial"]) + anyToString(delta["partial_json"])
			}
			content[idx] = blk
		case "content_block_stop":
			idx := anyToInt(ev["index"])
			if idx < 0 || idx >= len(content) {
				continue
			}
			blk, _ := content[idx].(map[string]any)
			if blk == nil {
				continue
			}
			if p := anyToString(blk["_partial"]); p != "" {
				var input any
				if json.Unmarshal([]byte(p), &input) == nil {
					blk["input"] = input
				} else if blk["input"] == nil {
					blk["input"] = map[string]any{}
				}
				delete(blk, "_partial")
			}
			content[idx] = blk
		case "message_delta":
			if msg != nil {
				if d, ok := ev["delta"].(map[string]any); ok {
					if v, exists := d["stop_reason"]; exists {
						msg["stop_reason"] = v
					}
					if v, exists := d["stop_sequence"]; exists {
						msg["stop_sequence"] = v
					}
				}
			}
			applyUsage(ev["usage"])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, u, err
	}
	if msg == nil {
		return nil, u, fmt.Errorf("upstream stream ended without a message")
	}
	msg["content"] = content
	if msg["type"] == nil {
		msg["type"] = "message"
	}
	msg["usage"] = map[string]any{
		"input_tokens":                u.input,
		"output_tokens":               u.output,
		"cache_creation_input_tokens": u.cacheWrite,
		"cache_read_input_tokens":     u.cacheRead,
	}
	raw, err := mimicry.EncodeBody(msg)
	return raw, u, err
}

func anyToInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	default:
		return 0, false
	}
}

func anyToInt(v any) int {
	i, ok := anyToInt64(v)
	if !ok {
		return -1
	}
	return int(i)
}

func anyToString(v any) string {
	s, _ := v.(string)
	return s
}
