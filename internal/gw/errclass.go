package gw

import "strings"

// ErrorClass is the operational action an upstream error body calls for.
// The keyword corpus is filtered from the channel-disable lists used by
// one-api/new-api family gateways down to errors Anthropic actually returns;
// classification routes each failure to the right account action instead of
// relying on status codes alone.
type ErrorClass int

const (
	ErrUnknown ErrorClass = iota
	ErrBanned      // account dead: disable permanently
	ErrGeoBlocked  // egress IP in an unsupported region — proxy problem, account is fine
	ErrModelAccess // account lacks this model — fail over, keep the account
	ErrBilling     // credits/spending cap exhausted — long cooldown
	ErrThinkingSig // historical thinking block signature rejected
)

var errPatterns = []struct {
	class ErrorClass
	keys  []string
}{
	{ErrGeoBlocked, []string{
		"unsupported countries",
		"access to anthropic models is not allowed",
		"your ip is not authorized",
	}},
	{ErrBanned, []string{
		"violation of our usage policy",
		"violation of our policies",
		"terms of use and policies",
		"organization has been disabled",
		"account is currently blocked",
		"has been suspended",
		"access has been disabled",
		"access was terminated",
		"identity verification is required",
	}},
	{ErrModelAccess, []string{
		"does not have access to model",
		"not available for this account",
		"access to this model",
		"channel program accounts",
		"must be verified to use the model",
		"data sharing to be enabled",
		"limited preview",
	}},
	{ErrBilling, []string{
		"insufficient balance",
		"credit balance is too low",
		"no credits remaining",
		"insufficient credits",
		"billing to be enabled",
		"monthly spending cap",
		"monthly spending limit",
	}},
	{ErrThinkingSig, []string{
		"invalid `signature` in `thinking`",
		"invalid signature in thinking",
		"invalid `signature` in `redacted_thinking`",
		"thinking.signature",
	}},
}

// classifyErrorBody maps an upstream error body to its operational class.
func classifyErrorBody(body string) ErrorClass {
	b := strings.ToLower(body)
	for _, p := range errPatterns {
		for _, k := range p.keys {
			if strings.Contains(b, k) {
				return p.class
			}
		}
	}
	return ErrUnknown
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
