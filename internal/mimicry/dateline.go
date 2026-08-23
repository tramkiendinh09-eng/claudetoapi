package mimicry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// ---- JSON helpers (order-preserving enough: map keys marshal sorted,
// arrays keep order; servers parse JSON so member order is not observable) ----

// DecodeBody parses a request body preserving number literals.
func DecodeBody(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var body map[string]any
	if err := dec.Decode(&body); err != nil {
		return nil, err
	}
	return body, nil
}

// EncodeBody marshals deterministically.
func EncodeBody(body map[string]any) ([]byte, error) {
	return json.Marshal(body)
}

// ReadJSONBody reads an http request body with a size limit and decodes it.
func ReadJSONBody(r *http.Request, limitBytes int64) (map[string]any, []byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, limitBytes))
	if err != nil {
		return nil, nil, err
	}
	body, err := DecodeBody(raw)
	if err != nil {
		return nil, raw, err
	}
	return body, raw, nil
}

// ---- dateline watermark normalization ----

// Some clients embed a steganographic watermark in the dateline sentence
// "Today's date is YYYY-MM-DD." when they detect a non-official base URL:
// one of four apostrophe code points (U+0027 U+2019 U+02BC U+02B9) in
// "Today's" crossed with one of two date separators (- or /). The real CLI
// 2.1.241 always emits ASCII + hyphen (verified in payload fn U$a), so we
// canonicalize every variant before forwarding.

var (
	datelineRe = regexp.MustCompile(`Today(['’ʼʹ])s date is (\d{4})[-/](\d{2})[-/](\d{2})\.`)
)

// NormalizeDateline canonicalizes watermarked datelines inside the system
// field and inside <system-reminder> blocks of message text. Returns the
// rewritten body when anything changed.
func NormalizeDateline(body map[string]any) bool {
	changed := false

	switch s := body["system"].(type) {
	case string:
		if n, c := normalizeText(s); c {
			body["system"] = n
			changed = true
		}
	case []any:
		for _, b := range s {
			blk, ok := b.(map[string]any)
			if !ok {
				continue
			}
			if t, ok := blk["text"].(string); ok {
				if n, c := normalizeText(t); c {
					blk["text"] = n
					changed = true
				}
			}
		}
	}

	if msgs, ok := body["messages"].([]any); ok {
		for _, m := range msgs {
			msg, ok := m.(map[string]any)
			if !ok {
				continue
			}
			switch c := msg["content"].(type) {
			case string:
				if n, ch := normalizeReminderScoped(c); ch {
					msg["content"] = n
					changed = true
				}
			case []any:
				for _, b := range c {
					blk, ok := b.(map[string]any)
					if !ok || blk["type"] != "text" {
						continue
					}
					if t, ok := blk["text"].(string); ok {
						if n, ch := normalizeReminderScoped(t); ch {
							blk["text"] = n
							changed = true
						}
					}
				}
			}
		}
	}
	return changed
}

func normalizeText(text string) (string, bool) {
	locs := datelineRe.FindAllStringSubmatchIndex(text, -1)
	if len(locs) == 0 {
		return text, false
	}
	var b strings.Builder
	b.Grow(len(text))
	prev := 0
	changed := false
	for _, m := range locs {
		full := text[m[0]:m[1]]
		canonical := fmt.Sprintf("Today's date is %s-%s-%s.",
			text[m[4]:m[5]], text[m[6]:m[7]], text[m[8]:m[9]])
		if full == canonical {
			continue
		}
		b.WriteString(text[prev:m[0]])
		b.WriteString(canonical)
		prev = m[1]
		changed = true
	}
	if !changed {
		return text, false
	}
	b.WriteString(text[prev:])
	return b.String(), true
}

var reminderRe = regexp.MustCompile(`(?s)<system-reminder>.*?</system-reminder>`)

// normalizeReminderScoped only rewrites text inside <system-reminder> blocks;
// user prose quoting a date is never touched.
func normalizeReminderScoped(text string) (string, bool) {
	if !strings.Contains(text, "<system-reminder>") {
		return text, false
	}
	locs := reminderRe.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return text, false
	}
	var b strings.Builder
	b.Grow(len(text))
	prev := 0
	changed := false
	for _, loc := range locs {
		b.WriteString(text[prev:loc[0]])
		n, c := normalizeText(text[loc[0]:loc[1]])
		if c {
			changed = true
		}
		b.WriteString(n)
		prev = loc[1]
	}
	if !changed {
		return text, false
	}
	b.WriteString(text[prev:])
	return b.String(), true
}

// IsClaudeCodeClient detects genuine CLI traffic: claude-cli UA plus a
// metadata.user_id, or a billing block in the body when an upstream gateway
// rewrote the UA.
func IsClaudeCodeClient(userAgent string, body map[string]any) bool {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(userAgent)), "claude-cli/") {
		if meta, ok := body["metadata"].(map[string]any); ok {
			if uid, _ := meta["user_id"].(string); uid != "" {
				return true
			}
		}
		if HasBillingBlock(body) {
			return true
		}
	}
	if HasBillingBlock(body) {
		return true
	}
	return false
}
