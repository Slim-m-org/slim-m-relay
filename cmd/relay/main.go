// SPDX-License-Identifier: Apache-2.0

// Command relay runs the slim-m push relay: a deliberately minimal, stateless-ish
// forwarder that lets self-hosted slim-m servers wake mobile devices over APNs and FCM. It
// is not the messaging backend - the home server encrypts every payload before it ever
// reaches the relay, and the relay only ever forwards that ciphertext plus a coarse kind.
// It never encrypts, decrypts, or logs payload content.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/nc1107/slim-m-relay/internal/api"
	"github.com/nc1107/slim-m-relay/internal/apns"
	"github.com/nc1107/slim-m-relay/internal/config"
	"github.com/nc1107/slim-m-relay/internal/fcm"
	"github.com/nc1107/slim-m-relay/internal/keys"
	"github.com/nc1107/slim-m-relay/internal/push"
)

func main() {
	// `relay -healthcheck` hits the local health endpoint and exits 0/1. Used as the
	// container healthcheck since the distroless image has no shell or curl.
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		os.Exit(healthcheck())
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	androidSender := buildFCM(cfg)
	iosSender := buildAPNs(cfg)

	if dir := filepath.Dir(cfg.DBPath); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("create db dir: %v", err)
		}
	}
	store, err := keys.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("keys store: %v", err)
	}
	defer store.Close()

	srv := api.New(cfg, iosSender, androidSender, store)

	if cfg.AdminToken == "" {
		log.Println("relay: admin endpoints disabled (RELAY_ADMIN_TOKEN unset)")
	}

	addr := fmt.Sprintf(":%d", cfg.Port)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Router(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("slim-m relay listening on %s", addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
}

// buildFCM wires the Android sender. An unset credentials path is not fatal: Android sends
// fail clearly through push.Unconfigured instead, so the relay still starts and serves
// everything else (iOS sends, registration, admin, health). A path that is set but
// unreadable is a startup misconfiguration and fails fast, like a malformed APNs key.
func buildFCM(cfg config.Config) push.Sender {
	if cfg.FCMCredentialsFile == "" {
		log.Println("relay: RELAY_FCM_CREDENTIALS_FILE unset; Android (FCM) sends will fail")
		return push.Unconfigured("fcm")
	}
	creds, err := os.ReadFile(cfg.FCMCredentialsFile)
	if err != nil {
		log.Fatalf("read FCM credentials: %v", err)
	}
	sender, err := fcm.New(context.Background(), creds)
	if err != nil {
		log.Fatalf("fcm: %v", err)
	}
	log.Printf("relay: forwarding Android pushes through Firebase project %q", sender.ProjectID())
	return sender
}

// buildAPNs wires the iOS sender. Incomplete credentials are not fatal: iOS sends fail
// clearly through push.Unconfigured instead, so the relay still starts and serves
// everything else. Credentials that are present but unusable (a malformed .p8 key, for
// instance) are treated as a startup misconfiguration and fail fast.
func buildAPNs(cfg config.Config) push.Sender {
	if cfg.APNsKeyPath == "" || cfg.APNsKeyID == "" || cfg.APNsTeamID == "" || cfg.APNsBundleID == "" {
		log.Println("relay: RELAY_APNS_* credentials incomplete; iOS (APNs) sends will fail")
		return push.Unconfigured("apns")
	}
	sender, err := apns.New(apns.Config{
		KeyPath:    cfg.APNsKeyPath,
		KeyID:      cfg.APNsKeyID,
		TeamID:     cfg.APNsTeamID,
		BundleID:   cfg.APNsBundleID,
		Production: cfg.APNsProduction,
	})
	if err != nil {
		log.Fatalf("apns: %v", err)
	}
	log.Printf("relay: forwarding iOS pushes for bundle %q (production=%v)", cfg.APNsBundleID, cfg.APNsProduction)
	return sender
}

// healthcheck performs a single GET against the local health endpoint, returning 0 when it
// responds 200 and 1 otherwise. Run via `relay -healthcheck` as the container probe.
func healthcheck() int {
	port := os.Getenv("RELAY_PORT")
	if port == "" {
		port = "8090"
	}
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
