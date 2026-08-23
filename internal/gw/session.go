package gw

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"claudetoapi/internal/mimicry"
)

// SessionHash derives the sticky-routing key from a decoded body:
//  1. session_id inside metadata.user_id (real CLI sessions),
//  2. hash of system+messages (third-party clients).
func SessionHash(body map[string]any) string {
	if meta, ok := body["metadata"].(map[string]any); ok {
		if uid, _ := meta["user_id"].(string); uid != "" {
			if sid := parseSessionID(uid); sid != "" {
				return sid
			}
		}
	}
	h := sha256.New()
	if sys, ok := body["system"].(string); ok {
		_, _ = h.Write([]byte(sys))
	}
	if msgs, ok := body["messages"].([]any); ok {
		raw, _ := json.Marshal(msgs)
		_, _ = h.Write(raw)
	}
	if h.Sum(nil) == nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// parseSessionID accepts both user_id forms:
// legacy "client:account:session" and 2.1.x JSON {"device_id",...}.
func parseSessionID(uid string) string {
	if strings.HasPrefix(uid, "{") {
		var v struct {
			SessionID string `json:"session_id"`
		}
		if json.Unmarshal([]byte(uid), &v) == nil {
			return v.SessionID
		}
		return ""
	}
	parts := strings.Split(uid, ":")
	if len(parts) == 3 && parts[2] != "" {
		return parts[2]
	}
	return ""
}

// chainState tracks the per-conversation billing chain (cc_prompt_id is one
// UUID per conversation; cc_prev_req links consecutive requests).
type chainState struct {
	PromptID  string
	LastReqID string
	Expires   time.Time
}

// Chain maintains conversation chains and sticky bindings in memory.
type Chain struct {
	mu       sync.Mutex
	chains   map[string]*chainState
	sticky   map[string]int64 // sessionHash -> account ID
	stickyAt map[string]time.Time
}

func NewChain() *Chain {
	return &Chain{
		chains:   map[string]*chainState{},
		sticky:   map[string]int64{},
		stickyAt: map[string]time.Time{},
	}
}

const (
	chainTTL    = 30 * time.Minute
	stickyTTL   = 30 * time.Minute
	cleanupEvery = 5 * time.Minute
)

// Next returns (promptID, prevReqID) for the conversation and advances the
// chain with a fresh request id. prevReqID is empty on the first request.
func (c *Chain) Next(sessionHash string) (promptID, prevReqID, reqID string) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked(now)

	st, ok := c.chains[sessionHash]
	if !ok || now.After(st.Expires) {
		st = &chainState{PromptID: mimicry.NewUUID()}
		c.chains[sessionHash] = st
	}
	st.Expires = now.Add(chainTTL)
	prevReqID = st.LastReqID
	reqID = mimicry.NewRequestID()
	st.LastReqID = reqID
	return st.PromptID, prevReqID, reqID
}

// Bind records the sticky session -> account mapping.
func (c *Chain) Bind(sessionHash string, accountID int64) {
	if sessionHash == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sticky[sessionHash] = accountID
	c.stickyAt[sessionHash] = time.Now()
}

// Sticky returns the bound account for the session, if fresh.
func (c *Chain) Sticky(sessionHash string) (int64, bool) {
	if sessionHash == "" {
		return 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	id, ok := c.sticky[sessionHash]
	if !ok || time.Since(c.stickyAt[sessionHash]) > stickyTTL {
		return 0, false
	}
	return id, true
}

// gcLocked prunes expired entries; caller holds mu.
func (c *Chain) gcLocked(now time.Time) {
	for k, st := range c.chains {
		if now.After(st.Expires) {
			delete(c.chains, k)
		}
	}
	for k, at := range c.stickyAt {
		if now.Sub(at) > stickyTTL {
			delete(c.stickyAt, k)
			delete(c.sticky, k)
		}
	}
}
