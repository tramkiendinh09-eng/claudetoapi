package mimicry

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

// UUIDFromSeed derives a stable v4-shaped UUID from an arbitrary seed, so
// conversations without a native session id still get a stable one.
func UUIDFromSeed(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ParseUserID extracts (deviceID, accountUUID, sessionID) from either the
// legacy concatenated form "device:account:session" or the 2.1.x JSON form.
func ParseUserID(uid string) (device, account, session string, ok bool) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return "", "", "", false
	}
	if strings.HasPrefix(uid, "{") {
		var v struct {
			DeviceID    string `json:"device_id"`
			AccountUUID string `json:"account_uuid"`
			SessionID   string `json:"session_id"`
		}
		if err := json.Unmarshal([]byte(uid), &v); err != nil {
			return "", "", "", false
		}
		return v.DeviceID, v.AccountUUID, v.SessionID, true
	}
	parts := strings.Split(uid, ":")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// RewriteUserIDOnly rewrites metadata.user_id to the account's stable device
// identity (JSON form) while leaving the rest of a genuine CLI body intact.
// This is the single body edit applied to real Claude Code traffic.
func RewriteUserIDOnly(body map[string]any, clientID, accountUUID, sessionID string) {
	if clientID == "" || sessionID == "" {
		return
	}
	newUID := UserIDJSON(clientID, accountUUID, sessionID)
	if meta, ok := body["metadata"].(map[string]any); ok {
		if uid, _ := meta["user_id"].(string); uid == newUID {
			return
		}
		meta["user_id"] = newUID
		return
	}
	body["metadata"] = map[string]any{"user_id": newUID}
}
