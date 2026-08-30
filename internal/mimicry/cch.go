package mimicry

import (
	"bytes"
	"fmt"
	"regexp"
)

// CCHSeed177 is the xxHash64 seed recovered for cch in Claude Code 2.1.177
// and still present as a little-endian immediate in 2.1.251 claude.exe.
// cch = xxHash64(canon(body), seed) & 0xfffff  (5 hex).
const CCHSeed177 = uint64(0x4D659218E32A3268)

const cchPlaceholder = "cch=00000"

var (
	cchFieldRe       = regexp.MustCompile(` cch=[0-9a-fA-F]+;`)
	cchEntrypointRe  = regexp.MustCompile(`cc_entrypoint=[^;]*;`)
	cchPlaceholderRe = regexp.MustCompile(`cch=00000`)
)

// BuildAttribution inserts the JS-layer placeholder. Native HTTP replaces
// cch=00000 on the wire for first-party traffic to api.anthropic.com
// (2.1.251: E=d==="firstParty"&&jo()||vertex ? " cch=00000;" : "").
func ensureCCHInAttribution(text string) string {
	if text == "" || !stringsContainsBilling(text) {
		return text
	}
	stripped := cchFieldRe.ReplaceAllString(text, "")
	if cchPlaceholderRe.MatchString(stripped) {
		return stripped
	}
	loc := cchEntrypointRe.FindStringIndex(stripped)
	if loc == nil {
		if stripped[len(stripped)-1] != ';' {
			stripped += ";"
		}
		return stripped + " cch=00000;"
	}
	return stripped[:loc[1]] + " cch=00000;" + stripped[loc[1]:]
}

func stringsContainsBilling(text string) bool {
	return len(text) >= 24 && (bytes.Contains([]byte(text), []byte("x-anthropic-billing-header:")))
}

// EnsureCCHPlaceholder puts cch=00000 after cc_entrypoint in the billing
// block so SealCCH can fill it. Existing cch values are wiped first — they
// were computed for a different body.
func EnsureCCHPlaceholder(body map[string]any) {
	if body == nil {
		return
	}
	switch sys := body["system"].(type) {
	case string:
		if next := ensureCCHInAttribution(sys); next != sys {
			body["system"] = next
		}
	case []any:
		for i, b := range sys {
			blk, ok := b.(map[string]any)
			if !ok {
				continue
			}
			t, _ := blk["text"].(string)
			if t == "" || !stringsContainsBilling(t) {
				continue
			}
			blk["text"] = ensureCCHInAttribution(t)
			sys[i] = blk
			return
		}
	}
}

func canonCCH(body map[string]any) ([]byte, error) {
	raw, err := EncodeBody(body)
	if err != nil {
		return nil, err
	}
	clone, err := DecodeBody(raw)
	if err != nil {
		return nil, err
	}
	if _, ok := clone["model"]; ok {
		clone["model"] = ""
	}
	delete(clone, "max_tokens")
	delete(clone, "fallbacks")
	return EncodeBody(clone)
}

// SealCCH replaces cch=00000 in an already-encoded /v1/messages body with
// the 5-hex digest. No placeholder → no-op (headless/custom BASE_URL paths
// omit the field).
func SealCCH(payload []byte) ([]byte, error) {
	if !bytes.Contains(payload, []byte(cchPlaceholder)) {
		return payload, nil
	}
	body, err := DecodeBody(payload)
	if err != nil {
		return nil, err
	}
	canon, err := canonCCH(body)
	if err != nil {
		return nil, err
	}
	h := xxh64(canon, CCHSeed177) & 0xfffff
	repl := fmt.Sprintf("cch=%05x", h)
	return bytes.Replace(payload, []byte(cchPlaceholder), []byte(repl), 1), nil
}
