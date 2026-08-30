package gw

import (
	"strings"
	"testing"

	"claudetoapi/internal/store"
)

func TestLinuxX64PersonaDeterministic(t *testing.T) {
	id := strings.Repeat("ab", 32)
	a := linuxX64PersonaFor(id)
	b := linuxX64PersonaFor(id)
	if a != b {
		t.Fatalf("persona not sticky: %+v vs %+v", a, b)
	}
	if a.Arch != "x64" || a.RuntimeVersion == "" || a.Terminal == "" || a.Shell == "" {
		t.Fatalf("incomplete persona: %+v", a)
	}
}

func TestLinuxX64PersonaDiverse(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 40; i++ {
		id := newClientID()
		p := linuxX64PersonaFor(id)
		seen[p.RuntimeVersion+"|"+p.Terminal+"|"+p.Shell] = true
	}
	if len(seen) < 3 {
		t.Fatalf("expected several personas, got %d: %v", len(seen), seen)
	}
}

func TestApplyMachinePersonaDoesNotJumpArch(t *testing.T) {
	fp := &store.Fingerprint{
		ClientID:       strings.Repeat("cd", 32),
		OS:             "Linux",
		Arch:           "arm64",
		Runtime:        "node",
		RuntimeVersion: "v24.3.0",
	}
	applyMachinePersona(fp)
	if fp.Arch != "arm64" || fp.RuntimeVersion != "v24.3.0" {
		t.Fatalf("live arch/runtime mutated: %+v", fp)
	}
	if fp.Terminal == "" || fp.Shell == "" {
		t.Fatal("expected terminal/shell to fill")
	}
}
