package mimicry

// HasSignedThinking reports whether the conversation already carries
// thinking / redacted_thinking blocks (with or without a signature). Those
// blocks must be forwarded byte-stable; changing betas or rewriting the
// text invalidates Anthropic's signature.
func HasSignedThinking(body map[string]any) bool {
	return walkThinking(body, func(blk map[string]any) bool {
		return true
	})
}

// StripThinkingBlocks removes thinking and redacted_thinking content blocks
// from the conversation. Anthropic accepts history without thinking; it
// rejects history with a bad signature. Used as a same-account retry after
// "Invalid `signature` in `thinking` block".
func StripThinkingBlocks(body map[string]any) bool {
	msgs, ok := body["messages"].([]any)
	if !ok {
		return false
	}
	changed := false
	for _, m := range msgs {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		blocks, ok := msg["content"].([]any)
		if !ok {
			continue
		}
		filtered := make([]any, 0, len(blocks))
		dropped := false
		for _, b := range blocks {
			blk, ok := b.(map[string]any)
			if !ok {
				filtered = append(filtered, b)
				continue
			}
			switch blk["type"] {
			case "thinking", "redacted_thinking":
				dropped = true
				continue
			}
			filtered = append(filtered, b)
		}
		if !dropped {
			continue
		}
		if len(filtered) == 0 {
			filtered = []any{map[string]any{"type": "text", "text": " "}}
		}
		msg["content"] = filtered
		changed = true
	}
	return changed
}

func walkThinking(body map[string]any, fn func(map[string]any) bool) bool {
	msgs, ok := body["messages"].([]any)
	if !ok {
		return false
	}
	for _, m := range msgs {
		msg, ok := m.(map[string]any)
		if !ok {
			continue
		}
		blocks, ok := msg["content"].([]any)
		if !ok {
			continue
		}
		for _, b := range blocks {
			blk, ok := b.(map[string]any)
			if !ok {
				continue
			}
			switch blk["type"] {
			case "thinking", "redacted_thinking":
				if fn(blk) {
					return true
				}
			}
		}
	}
	return false
}
