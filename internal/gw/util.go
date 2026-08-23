package gw

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
)

func readRand(b []byte) (int, error) { return rand.Read(b) }

func hexEncode(b []byte) string { return hex.EncodeToString(b) }

// secureEqual compares two strings in constant time; an empty expected key
// rejects everything.
func secureEqual(got, want string) bool {
	if want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// secureHasKey reports whether got matches any of keys, using
// constant-time comparisons per key.
func secureHasKey(got string, keys []string) bool {
	for _, k := range keys {
		if secureEqual(got, k) {
			return true
		}
	}
	return false
}

// SecureHasKey is the exported form for the main package's auth wrapper.
func SecureHasKey(got string, keys []string) bool {
	return secureHasKey(got, keys)
}
