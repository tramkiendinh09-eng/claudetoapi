package gw

import (
	"encoding/json"
	"os"
	"strings"

	"claudetoapi/internal/mimicry"
)

func bodyKeys(body map[string]any) []string {
	if body == nil {
		return nil
	}
	out := make([]string, 0, len(body))
	for k := range body {
		out = append(out, k)
	}
	return out
}

func lenAny(v any) int {
	switch t := v.(type) {
	case []any:
		return len(t)
	case string:
		return len(t)
	default:
		return 0
	}
}

func toolNames(body map[string]any) []string {
	tools, ok := body["tools"].([]any)
	if !ok {
		return nil
	}
	var names []string
	for i, t := range tools {
		if i >= 8 {
			break
		}
		m, ok := t.(map[string]any)
		if !ok {
			continue
		}
		if n, _ := m["name"].(string); n != "" {
			names = append(names, n)
		}
	}
	return names
}

func msgSummary(body map[string]any) []map[string]any {
	msgs, ok := body["messages"].([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(msgs))
	for i, m := range msgs {
		if i >= 6 {
			break
		}
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		item := map[string]any{"role": msg["role"]}
		switch c := msg["content"].(type) {
		case string:
			item["content"] = "string"
			item["n"] = len(c)
		case []any:
			types := make([]string, 0, len(c))
			for _, b := range c {
				blk, _ := b.(map[string]any)
				if blk != nil {
					if t, _ := blk["type"].(string); t != "" {
						types = append(types, t)
					}
				}
			}
			item["content"] = types
			item["n"] = len(c)
		}
		out = append(out, item)
	}
	return out
}

func sysPrefix(body map[string]any, n int) string {
	switch s := body["system"].(type) {
	case string:
		if len(s) > n {
			return s[:n]
		}
		return s
	case []any:
		if len(s) == 0 {
			return ""
		}
		blk, _ := s[0].(map[string]any)
		if blk == nil {
			return ""
		}
		t, _ := blk["text"].(string)
		if len(t) > n {
			return t[:n]
		}
		return t
	}
	return ""
}

func billingLine(body map[string]any) string {
	sys, ok := body["system"].([]any)
	if !ok {
		return ""
	}
	for _, b := range sys {
		blk, ok := b.(map[string]any)
		if !ok {
			continue
		}
		t, _ := blk["text"].(string)
		if strings.HasPrefix(t, "x-anthropic-billing-header:") {
			if len(t) > 400 {
				return t[:400]
			}
			return t
		}
	}
	return ""
}

func write429Shape(path string, body map[string]any, opts forwardOpts, payload []byte, ua string) {
	if path == "" || body == nil {
		return
	}
	shape := map[string]any{
		"ua":                    shortUA(ua),
		"cc":                    opts.IsCC,
		"orig_stream":           opts.Stream,
		"count_tokens":          opts.CountTokens,
		"payload_len":           len(payload),
		"payload_stream_true":   strings.Contains(string(payload), `"stream":true`),
		"payload_stream_false":  strings.Contains(string(payload), `"stream":false`),
		"keys":                  bodyKeys(body),
		"model":                 body["model"],
		"max_tokens":            body["max_tokens"],
		"stream":                body["stream"],
		"speed":                 body["speed"],
		"temperature":           body["temperature"],
		"thinking":              body["thinking"],
		"tool_choice":           body["tool_choice"],
		"n_tools":               lenAny(body["tools"]),
		"tool_names":            toolNames(body),
		"n_msgs":                lenAny(body["messages"]),
		"msgs":                  msgSummary(body),
		"n_sys":                 lenAny(body["system"]),
		"sys0_prefix":           sysPrefix(body, 240),
		"billing":               billingLine(body),
		"first_user_len":        len(mimicry.FirstUserText(body)),
	}
	raw, err := json.MarshalIndent(shape, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, raw, 0o600)
}
