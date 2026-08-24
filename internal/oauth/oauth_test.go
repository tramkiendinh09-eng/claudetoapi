package oauth

import (
	"context"
	"testing"
)

// A failed exchange must keep the PKCE session retryable: burning the state
// on the first error forced the operator through the whole browser flow
// again just because a paste glitched.
func TestFailedExchangeKeepsSession(t *testing.T) {
	c := New("")
	res, err := c.BeginBrowserFlow()
	if err != nil {
		t.Fatal(err)
	}
	// exchange with a garbage code against the real endpoint: expect failure
	_, err = c.CompleteBrowserFlow(context.Background(), "garbage-code", res.State)
	if err == nil {
		t.Fatal("garbage code must fail")
	}
	// the session must still exist so the operator can retry
	pendingMu.Lock()
	_, alive := pending[res.State]
	pendingMu.Unlock()
	if !alive {
		t.Fatal("failed exchange must not consume the state session")
	}
}
