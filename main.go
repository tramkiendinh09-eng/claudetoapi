// claudetoapi — a focused Claude reverse-proxy gateway that forwards
// Anthropic /v1/messages traffic through Claude Code OAuth subscriptions with
// byte-faithful CLI mimicry (TLS fingerprint, header wire format, request
// body shape, billing attribution chain).
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
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
const version = "0.5.5"

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
	admin := gw.NewAdmin(cfg, st, gateway, version)
	admin.SetConfigPath(*cfgPath)

	mux := http.NewServeMux()

	// Gateway endpoints (API-key auth, CORS-enabled for browser SDKs).
	mux.HandleFunc("POST /v1/messages", apiKeyAuth(cfg)(gateway.HandleMessages))
	mux.HandleFunc("POST /v1/messages/count_tokens", apiKeyAuth(cfg)(gateway.HandleCountTokens))
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

	slog.Info("claudetoapi listening", "addr", cfg.Listen, "accounts", len(st.Snapshot()), "version", version)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           withCORS(mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Serve until SIGINT/SIGTERM, then drain: stop accepting, let in-flight
	// streams finish (15s cap), flush the usage ledger and telemetry batches.
	done := make(chan struct{})
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server", "error", err)
			os.Exit(1)
		}
		close(done)
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case <-sig:
		slog.Info("shutting down")
	case <-done:
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	gateway.Telemetry().StopAll()
	gateway.CloseUsage()
	slog.Info("stopped")
}

// withCORS allows browser-hosted SDKs to call the gateway directly.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// apiKeyAuth wraps a handler with API-key verification (constant-time).
func apiKeyAuth(cfg *config.Config) func(http.HandlerFunc) http.HandlerFunc {
	keys := make([]string, 0, len(cfg.APIKeys))
	for _, k := range cfg.APIKeys {
		if k = strings.TrimSpace(k); k != "" {
			keys = append(keys, k)
		}
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
			if token == "" || !gw.SecureHasKey(token, keys) {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`))
				return
			}
			next(w, r)
		}
	}
}
