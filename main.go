// claudetoapi — a focused Claude reverse-proxy gateway that forwards
// Anthropic /v1/messages traffic through Claude Code OAuth subscriptions with
// byte-faithful CLI mimicry (TLS fingerprint, header wire format, request
// body shape, billing attribution chain).
package main

import (
	"embed"
	"flag"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
	// Embed the IANA timezone database: Windows hosts have no system tzdata,
	// and per-proxy timezone binding needs it.
	_ "time/tzdata"

	"claudetoapi/internal/config"
	"claudetoapi/internal/gw"
	"claudetoapi/internal/mimicry"
	"claudetoapi/internal/store"
)

//go:embed web
var webFS embed.FS

// version is reported by /admin/info and the console.
const version = "0.1.0"

func main() {
	cfgPath := flag.String("c", "config.json", "path to config.json")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("config", "error", err)
		os.Exit(1)
	}

	st, err := store.Open(cfg.AccountsDir)
	if err != nil {
		slog.Error("store", "error", err)
		os.Exit(1)
	}

	// Operator-supplied expansion prompt (recommended: the real ~27KB block
	// captured from the CLI, see README).
	mimicry.SetExpansionFile(cfg.AccountsDir + string(os.PathSeparator) + "expansion_prompt.txt")

	gateway := gw.New(cfg, st)
	gateway.SetTelemetry(gw.NewTelemetryManager(gateway))
	admin := gw.NewAdmin(cfg, st, gateway)

	mux := http.NewServeMux()

	// Gateway endpoints (API-key auth).
	mux.HandleFunc("POST /v1/messages", apiKeyAuth(cfg)(gateway.HandleMessages))
	mux.HandleFunc("POST /v1/messages/count_tokens", apiKeyAuth(cfg)(gateway.HandleMessages))
	mux.HandleFunc("GET /v1/models", apiKeyAuth(cfg)(gateway.HandleModels))

	admin.Mount(mux)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// Embedded web console (single-page, no external dependencies).
	webRoot, err := fs.Sub(webFS, "web")
	if err != nil {
		slog.Error("web embed", "error", err)
		os.Exit(1)
	}
	fileServer := http.FileServer(http.FS(webRoot))
	mux.HandleFunc("GET /", fileServer.ServeHTTP)

	// Background token refresher: rotate tokens expiring within 3 minutes.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			gateway.RefreshExpiring()
		}
	}()

	// Graceful shutdown: flush telemetry batches on exit.
	defer gateway.Telemetry().StopAll()

	slog.Info("claudetoapi listening", "addr", cfg.Listen, "accounts", len(st.Snapshot()))
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("server", "error", err)
		os.Exit(1)
	}
}

// apiKeyAuth wraps a handler with API-key verification.
func apiKeyAuth(cfg *config.Config) func(http.HandlerFunc) http.HandlerFunc {
	keys := map[string]bool{}
	for _, k := range cfg.APIKeys {
		keys[strings.TrimSpace(k)] = true
	}
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token := ""
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				token = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
			}
			if token == "" {
				token = r.Header.Get("x-api-key")
			}
			if token == "" || !keys[token] {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`))
				return
			}
			next(w, r)
		}
	}
}
