// Copyright 2025 CompliK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package main provides the entry point for the ProcScan process monitoring and security scanning tool.
package main

import (
	"context"
	"errors"
	"flag"
	"math/rand/v2"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bearslyricattack/CompliK/procscan/internal/config"
	"github.com/bearslyricattack/CompliK/procscan/internal/core/scanner"
	"github.com/bearslyricattack/CompliK/procscan/internal/health"
	legacy "github.com/bearslyricattack/CompliK/procscan/pkg/logger/legacy"
	"github.com/bearslyricattack/CompliK/procscan/pkg/metrics"
	"github.com/sirupsen/logrus"
)

func main() {
	configPath := flag.String("config", "", "path to configuration file")

	flag.Parse()

	legacy.L.Info("ProcScan is starting...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go handleSignals(cancel)

	loader := config.NewLoader(*configPath)
	cfg, err := loader.LoadLocal()
	if err != nil {
		legacy.L.Fatalf("Failed to load initial configuration: %v", err)
	}

	// Set log level from initial configuration
	if cfg.Scanner.LogLevel != "" {
		legacy.SetLevel(cfg.Scanner.LogLevel)
	}

	s := scanner.NewScanner(cfg)
	healthServer := health.NewServer(cfg.Scanner.HealthPort, s.Ready)
	go func() {
		if err := healthServer.Start(); err != nil {
			legacy.L.WithError(err).Error("Health server stopped unexpectedly")
			cancel()
		}
	}()
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := healthServer.Stop(shutdownCtx); err != nil {
			legacy.L.WithError(err).Warn("Failed to stop health server")
		}
	}()

	if err := waitForInitialRules(ctx, loader, s); err != nil {
		legacy.L.WithError(err).Error("Stopped before a valid ruleset became available")
		return
	}
	legacy.L.Info("Initial configuration and rules loaded successfully")
	go refreshRules(ctx, loader, s)

	// Setup configuration watcher
	configWatcher, err := config.NewWatcher(loader, s.UpdateConfig)
	if err != nil {
		legacy.L.WithError(err).
			Warn("Failed to create configuration watcher, hot-reload will be unavailable")
	} else {
		if err := configWatcher.Start(ctx); err != nil {
			legacy.L.WithError(err).
				Warn("Failed to start configuration watcher, hot-reload will be unavailable")
		} else {
			defer func() {
				if err := configWatcher.Stop(); err != nil {
					legacy.L.WithError(err).Warn("Failed to stop configuration watcher")
				}
			}()
		}
	}

	// Start scanner
	if err := s.Start(ctx); err != nil {
		legacy.L.Errorf("Failed to start scanner: %v", err)
		return
	}
}

func waitForInitialRules(ctx context.Context, loader *config.Loader, s *scanner.Scanner) error {
	for {
		config, err := loader.Refresh(ctx, s.CurrentConfig())
		if err == nil {
			err = s.ApplyConfig(config)
			if err == nil && s.Ready() {
				metrics.RulesRefreshSuccessTotal.Inc()
				return nil
			}
			if err == nil {
				err = errors.New("loaded ruleset is not ready")
			}
		}
		metrics.RulesRefreshFailuresTotal.Inc()
		legacy.L.WithError(err).Warn("No valid ruleset available; scanner remains NotReady")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jittered(5 * time.Second)):
		}
	}
}

func refreshRules(ctx context.Context, loader *config.Loader, s *scanner.Scanner) {
	for {
		config := s.CurrentConfig()
		interval := 30 * time.Second
		if config != nil && config.Scanner.RulesRefreshInterval > 0 {
			interval = config.Scanner.RulesRefreshInterval
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(jittered(interval)):
		}

		refreshed, err := loader.Refresh(ctx, s.CurrentConfig())
		if err != nil {
			metrics.RulesRefreshFailuresTotal.Inc()
			legacy.L.WithError(err).Warn("Rule refresh failed; keeping the last valid ruleset")
			continue
		}
		if err := s.ApplyConfig(refreshed); err != nil {
			metrics.RulesRefreshFailuresTotal.Inc()
			legacy.L.WithError(err).Warn("Rule refresh rejected; keeping the last valid ruleset")
			continue
		}
		metrics.RulesRefreshSuccessTotal.Inc()
	}
}

func jittered(interval time.Duration) time.Duration {
	if interval <= 0 {
		return time.Second
	}
	factor := 0.8 + rand.Float64()*0.4
	return time.Duration(float64(interval) * factor)
}

// handleSignals handles OS signals for graceful shutdown
func handleSignals(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	legacy.L.WithFields(logrus.Fields{
		"signal": sig.String(),
	}).Info("Received shutdown signal, preparing graceful shutdown...")
	cancel()
}
