// Field-parity checker: compares a claudetoapi-produced event against the
// captured ground-truth sample field by field. Run:
//
//	go run ./cmd/telcheck ../../analysis/claude-code/event_logging_ground_truth.json
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"claudetoapi/internal/telemetry"
)

type record struct {
	URL     string
	Headers map[string]string
	Body    []byte
}

type capture struct{ reqs []record }

func (c *capture) Post(ctx context.Context, url string, headers map[string]string, body []byte) (int, []byte, error) {
	c.reqs = append(c.reqs, record{url, headers, body})
	return 200, []byte(`{}`), nil
}

func main() {
	gtPath := "../../analysis/claude-code/event_logging_ground_truth.json"
	if len(os.Args) > 1 {
		gtPath = os.Args[1]
	}
	raw, err := os.ReadFile(gtPath)
	if err != nil {
		fmt.Println("read ground truth:", err)
		os.Exit(1)
	}
	var gt struct {
		Events []struct {
			EventData map[string]any `json:"event_data"`
		} `json:"events"`
	}
	if err := json.Unmarshal(raw, &gt); err != nil {
		fmt.Println("parse ground truth:", err)
		os.Exit(1)
	}

	// Produce our own event with matching session identity.
	cap := &capture{}
	tele := telemetry.New(telemetry.DeviceIdentity{
		ClientID: "df7f00c8a71a7cd61ce9096069cf776de8d48dbf425007f6d1f4f45f5533f452",
		CLIVersion: "2.1.241", UserAgent: "claude-cli/2.1.241 (external, cli)",
		Entrypoint: "cli", Env: telemetry.DefaultEnv("v24.3.0", "2026-08-22T22:46:48Z"),
	}, "", cap)
	tele.NoteSession("38223b36-f8cb-42f6-bb57-6057666f341a", "claude-opus-5[1m]", "")
	tele.QueryPrompt("a14f546e-59a7-412e-8faf-ee5dc9deeb09", 1, 12)
	tele.BootSequence()
	_ = tele.Flush(context.Background())

	var ours struct {
		Events []struct {
			EventData map[string]any `json:"event_data"`
		} `json:"events"`
	}
	if err := json.Unmarshal(cap.reqs[0].Body, &ours); err != nil {
		fmt.Println("parse ours:", err)
		os.Exit(1)
	}

	gtSample := gt.Events[0].EventData
	ourSample := ours.Events[0].EventData

	// 1) key set parity
	gtKeys := keys(gtSample)
	ourKeys := keys(ourSample)
	missing := diff(gtKeys, ourKeys)
	extra := diff(ourKeys, gtKeys)
	fmt.Printf("== envelope keys ==\nground truth: %v\nours:         %v\n", gtKeys, ourKeys)
	if len(missing) > 0 {
		fmt.Printf("MISSING from ours: %v\n", missing)
	}
	if len(extra) > 0 {
		fmt.Printf("EXTRA in ours: %v\n", extra)
	}

	// 2) env keys parity
	gtEnv := gtSample["env"].(map[string]any)
	ourEnv := ourSample["env"].(map[string]any)
	fmt.Printf("\n== env keys ==\nmissing from ours: %v\nextra in ours: %v\n",
		diff(keys(gtEnv), keys(ourEnv)), diff(keys(ourEnv), keys(gtEnv)))

	// 3) value-class comparison (type + constant values)
	fmt.Println("\n== value parity (non-volatile fields) ==")
	for _, k := range []string{"user_type", "is_interactive", "entrypoint", "client_type", "model", "betas", "session_id", "device_id"} {
		fmt.Printf("%-14s GT=%v  OURS=%v  match=%v\n", k, gtSample[k], ourSample[k], fmt.Sprint(gtSample[k]) == fmt.Sprint(ourSample[k]))
	}
	for _, k := range []string{"platform", "arch", "version", "shell", "node_version"} {
		fmt.Printf("env.%-10s GT=%v  OURS=%v  match=%v\n", k, gtEnv[k], ourEnv[k], fmt.Sprint(gtEnv[k]) == fmt.Sprint(ourEnv[k]))
	}

	// 4) process/additional_metadata decode parity (schema keys)
	gtProc := decodeB64(gtSample["process"].(string))
	ourProc := decodeB64(ourSample["process"].(string))
	fmt.Printf("\n== process keys ==\nmissing: %v  extra: %v\n",
		diff(keys(gtProc), keys(ourProc)), diff(keys(ourProc), keys(gtProc)))

	fmt.Println("\nDONE")
}

func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func diff(a, b []string) []string {
	bset := map[string]bool{}
	for _, x := range b {
		bset[x] = true
	}
	var out []string
	for _, x := range a {
		if !bset[x] {
			out = append(out, x)
		}
	}
	return out
}

func decodeB64(s string) map[string]any {
	raw, _ := base64.StdEncoding.DecodeString(s)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

