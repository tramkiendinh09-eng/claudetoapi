// Package store persists gateway accounts as a single JSON document with
// atomic rewrite. It is intentionally simple: claudetoapi targets a small
// pool of Claude OAuth accounts on one node.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Credentials holds OAuth token material.
type Credentials struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	// ExpiresAt is RFC3339; access tokens live ~1 year but refreshes advance it.
	ExpiresAt string `json:"expires_at,omitempty"`
}

// Fingerprint is the per-account persistent client identity.
// One OAuth token must present exactly one machine: UA/SDK may ride a
// one-way CLI version upgrade, but OS/arch/runtime stay sticky for the
// life of the account. Inbound client UAs are never adopted onto this
// record (that mix of passthrough + mimic is what got a pool token banned).
type Fingerprint struct {
	ClientID       string `json:"client_id"`                  // 64-hex device id
	Entrypoint     string `json:"entrypoint"`                 // cc_entrypoint persona
	Profile        string `json:"profile"`                    // CLI version profile name
	UserAgent      string `json:"user_agent,omitempty"`       // sticky outbound UA
	SDKVersion     string `json:"sdk_version,omitempty"`      // paired X-Stainless-Package-Version
	OS             string `json:"os,omitempty"`               // X-Stainless-OS, sticky
	Arch           string `json:"arch,omitempty"`             // X-Stainless-Arch, sticky
	Runtime        string `json:"runtime,omitempty"`          // X-Stainless-Runtime, sticky
	RuntimeVersion string `json:"runtime_version,omitempty"`  // X-Stainless-Runtime-Version, sticky
	UpdatedAt      int64  `json:"updated_at"`
}

// RateWindow is the last observed state of one unified rate-limit window
// (5h or 7d) harvested from upstream response headers.
type RateWindow struct {
	Utilization float64   `json:"utilization"` // 0..1
	ResetAt     time.Time `json:"reset_at"`
}

// Expired reports whether the window has already reset (stale data).
func (rw *RateWindow) Expired(now time.Time) bool {
	return rw == nil || !now.Before(rw.ResetAt)
}

// Account is one upstream Claude OAuth subscription.
type Account struct {
	ID          int64       `json:"id"`
	Name        string      `json:"name"`
	Type        string      `json:"type"` // "oauth"
	Proxy       string      `json:"proxy,omitempty"` // named proxy pool entry
	ProxyURL    string      `json:"proxy_url,omitempty"` // raw proxy URL (fallback)
	Credentials Credentials `json:"credentials"`
	Extra      struct {
		AccountUUID string `json:"account_uuid,omitempty"`
		Email       string `json:"email,omitempty"`
	} `json:"extra"`
	Fingerprint *Fingerprint `json:"fingerprint,omitempty"`

	// Runtime state (persisted so cooldowns survive restarts).
	Status           string     `json:"status"` // active | error
	Error            string     `json:"error,omitempty"`
	RateLimitedUntil *time.Time `json:"rate_limited_until,omitempty"`
	RateLimitReason  string     `json:"rate_limit_reason,omitempty"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	Concurrency      int        `json:"concurrency,omitempty"`

	// Last observed unified rate-limit windows (from success headers).
	RateWindow5h *RateWindow `json:"rate_window_5h,omitempty"`
	RateWindow7d *RateWindow `json:"rate_window_7d,omitempty"`

	// OutputStyle overrides the global default for this account ("",
	// "concise", "proactive"). A per-account style also mirrors how real
	// users each pick their own setting.
	OutputStyle string `json:"output_style,omitempty"`
}

// Active reports whether the account can be scheduled now.
func (a *Account) Active(now time.Time) bool {
	if a.Status != "active" {
		return false
	}
	if a.RateLimitedUntil != nil && now.Before(*a.RateLimitedUntil) {
		return false
	}
	return true
}

type disk struct {
	NextID   int64      `json:"next_id"`
	Accounts []*Account `json:"accounts"`
}

// Store is a mutex-guarded JSON-file account store.
type Store struct {
	mu   sync.Mutex
	path string
	d    disk
}

// Open loads (or initializes) the store at dir/accounts.json.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	s := &Store{path: filepath.Join(dir, "accounts.json")}
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		s.d = disk{NextID: 1}
		return s, s.flushLocked()
	}
	if err != nil {
		return nil, fmt.Errorf("read accounts: %w", err)
	}
	if err := json.Unmarshal(raw, &s.d); err != nil {
		return nil, fmt.Errorf("parse accounts: %w", err)
	}
	if s.d.NextID == 0 {
		s.d.NextID = 1
	}
	return s, nil
}

// Add appends a new account and assigns its ID.
func (s *Store) Add(a *Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a.ID = s.d.NextID
	s.d.NextID++
	if a.Type == "" {
		a.Type = "oauth"
	}
	if a.Status == "" {
		a.Status = "active"
	}
	if a.Concurrency <= 0 {
		a.Concurrency = 2
	}
	s.d.Accounts = append(s.d.Accounts, a)
	return s.flushLocked()
}

// Update applies fn to the account with the given id and persists.
func (s *Store) Update(id int64, fn func(*Account)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.d.Accounts {
		if a.ID == id {
			fn(a)
			return s.flushLocked()
		}
	}
	return fmt.Errorf("account %d not found", id)
}

// Snapshot returns a shallow copy of all accounts.
func (s *Store) Snapshot() []*Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Account, len(s.d.Accounts))
	copy(out, s.d.Accounts)
	return out
}

// Get returns the account with the given id.
func (s *Store) Get(id int64) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.d.Accounts {
		if a.ID == id {
			return a, nil
		}
	}
	return nil, fmt.Errorf("account %d not found", id)
}

// Delete removes the account with the given id.
func (s *Store) Delete(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.d.Accounts {
		if a.ID == id {
			s.d.Accounts = append(s.d.Accounts[:i], s.d.Accounts[i+1:]...)
			return s.flushLocked()
		}
	}
	return fmt.Errorf("account %d not found", id)
}

// flushLocked writes the store atomically; caller must hold mu.
func (s *Store) flushLocked() error {
	raw, err := json.MarshalIndent(&s.d, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
