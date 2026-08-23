package mimicry

import (
	"regexp"
	"strings"
)

// canonicalDatelineRe matches the already-canonical dateline sentence (ASCII
// apostrophe, hyphen separators) produced by NormalizeDateline — or by the
// real CLI, which emits this form natively.
var canonicalDatelineRe = regexp.MustCompile(`Today's date is (\d{4})-(\d{2})-(\d{2})\.`)

// ShiftDatelines rewrites the date inside every canonical dateline sentence
// to `today` in the given timezone.
//
// Rationale: the CLI stamps its local calendar date into the system prompt.
// A gateway account that egresses through, say, a US proxy while the caller
// sits in UTC+8 will emit "tomorrow's" date for ~half of each day — a clean
// IP-vs-prompt contradiction. Shifting to the exit timezone's date restores
// consistency; the CLI also refreshes the dateline to the current date on
// every turn, so rewriting stale dates matches genuine behavior.
func ShiftDatelines(body map[string]any, today string) bool {
	if len(today) != 10 {
		return false
	}
	shift := func(text string) (string, bool) {
		if !strings.Contains(text, "date is ") {
			return text, false
		}
		changed := false
		out := canonicalDatelineRe.ReplaceAllStringFunc(text, func(m string) string {
			sub := canonicalDatelineRe.FindStringSubmatch(m)
			if sub == nil {
				return m
			}
			if sub[1]+"-"+sub[2]+"-"+sub[3] == today {
				return m
			}
			changed = true
			return "Today's date is " + today + "."
		})
		if !changed {
			return text, false
		}
		return out, true
	}

	changed := false
	switch s := body["system"].(type) {
	case string:
		if n, c := shift(s); c {
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
				if n, c := shift(t); c {
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
				if n, ch := shiftReminder(c, shift); ch {
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
						if n, ch := shiftReminder(t, shift); ch {
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

func shiftReminder(text string, shift func(string) (string, bool)) (string, bool) {
	if !strings.Contains(text, "<system-reminder>") {
		return text, false
	}
	locs := reminderRe.FindAllStringIndex(text, -1)
	if len(locs) == 0 {
		return text, false
	}
	var b strings.Builder
	prev := 0
	changed := false
	for _, loc := range locs {
		b.WriteString(text[prev:loc[0]])
		n, c := shift(text[loc[0]:loc[1]])
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
