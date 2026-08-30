package gw

import (
	"crypto/sha256"
	"encoding/binary"

	"claudetoapi/internal/store"
)

// linuxX64Persona is one plausible official-CLI machine on glibc x86_64.
// OS/arch stay Linux/x64 (the VPS); node version / TERM / shell vary so two
// OAuth tokens do not share a bitwise-identical env fingerprint.
type linuxX64Persona struct {
	RuntimeVersion string
	Terminal       string
	Shell          string
	Arch           string
}

var linuxX64Personas = []linuxX64Persona{
	{RuntimeVersion: "v24.3.0", Terminal: "xterm-256color", Shell: "bash", Arch: "x64"},
	{RuntimeVersion: "v24.3.0", Terminal: "screen", Shell: "bash", Arch: "x64"},
	{RuntimeVersion: "v24.4.1", Terminal: "xterm-256color", Shell: "zsh", Arch: "x64"},
	{RuntimeVersion: "v22.16.0", Terminal: "tmux-256color", Shell: "bash", Arch: "x64"},
	{RuntimeVersion: "v24.1.0", Terminal: "xterm", Shell: "bash", Arch: "x64"},
	{RuntimeVersion: "v24.5.0", Terminal: "xterm-256color", Shell: "zsh", Arch: "x64"},
	{RuntimeVersion: "v22.17.1", Terminal: "xterm-256color", Shell: "sh", Arch: "x64"},
	{RuntimeVersion: "v24.3.0", Terminal: "tmux", Shell: "bash", Arch: "x64"},
}

func linuxX64PersonaFor(clientID string) linuxX64Persona {
	sum := sha256.Sum256([]byte(clientID))
	n := binary.BigEndian.Uint32(sum[:4])
	return linuxX64Personas[int(n)%len(linuxX64Personas)]
}

// applyMachinePersona fills empty fingerprint machine fields from a
// clientID-derived persona. Already-set OS/arch/runtime are left alone so a
// live token never jumps architecture.
func applyMachinePersona(fp *store.Fingerprint) {
	if fp == nil || fp.ClientID == "" {
		return
	}
	p := linuxX64PersonaFor(fp.ClientID)
	if fp.OS == "" {
		fp.OS = "Linux"
	}
	if fp.Arch == "" {
		fp.Arch = p.Arch
	}
	if fp.Runtime == "" {
		fp.Runtime = "node"
	}
	if fp.RuntimeVersion == "" {
		fp.RuntimeVersion = p.RuntimeVersion
	}
	if fp.Terminal == "" {
		fp.Terminal = p.Terminal
	}
	if fp.Shell == "" {
		fp.Shell = p.Shell
	}
}
