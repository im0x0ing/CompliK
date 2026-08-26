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

// Package scanner provides the core process scanning and threat detection functionality
// for ProcScan, including scheduling, analysis, and response actions.
package scanner

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/bearslyricattack/CompliK/procscan/internal/core/alert"
	"github.com/bearslyricattack/CompliK/procscan/internal/core/processor"
	legacy "github.com/bearslyricattack/CompliK/procscan/pkg/logger/legacy"
	"github.com/bearslyricattack/CompliK/procscan/pkg/metrics"
	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
	"github.com/sirupsen/logrus"
)

type Scanner struct {
	config     *models.Config
	processor  *processor.Processor
	metrics    *metrics.Collector
	metricsSrv *metrics.Server
	mu         sync.RWMutex
	ticker     *time.Ticker
}

// ThreatInfo represents threat information structure
type ThreatInfo struct {
	PodName     string
	Namespace   string
	ProcessName string
	ProcessCmd  string
	ThreatType  string
	Severity    string
	Description string
	Labels      map[string]string
}

// NewScanner creates a new scanner instance with the provided configuration
func NewScanner(config *models.Config) *Scanner {
	// Initialize metrics collector
	metricsCollector := metrics.NewCollector()

	// Initialize metrics server
	var metricsServer *metrics.Server
	if config.Metrics.Enabled {
		metricsServer = metrics.NewMetricsServerFromConfig(config.Metrics)
		legacy.L.WithFields(logrus.Fields{
			"port": config.Metrics.Port,
			"path": config.Metrics.Path,
		}).Info("Metrics server configured")
	} else {
		legacy.L.Info("Metrics server disabled")
	}

	return &Scanner{
		config:     config,
		processor:  processor.NewProcessor(config),
		metrics:    metricsCollector,
		metricsSrv: metricsServer,
	}
}

func (s *Scanner) Ready() bool {
	return s != nil && s.processor != nil && s.processor.Ready()
}

func (s *Scanner) CurrentConfig() *models.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.config == nil {
		return nil
	}
	copy := *s.config
	return &copy
}

// ApplyConfig validates and atomically applies a scanner configuration.
func (s *Scanner) ApplyConfig(newConfig *models.Config) error {
	if newConfig == nil {
		return errors.New("config is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.config != nil && newConfig.ProcscanRules.RulesetRevision < s.config.ProcscanRules.RulesetRevision {
		return errors.New("ruleset revision rollback is not allowed")
	}

	if err := s.processor.UpdateConfig(newConfig); err != nil {
		return err
	}

	legacy.L.Info("Applying new configuration...")

	oldConfig := s.config
	s.config = newConfig

	if oldConfig.Scanner.LogLevel != newConfig.Scanner.LogLevel {
		legacy.SetLevel(newConfig.Scanner.LogLevel)
	}

	oldInterval := oldConfig.Scanner.ScanInterval

	newInterval := newConfig.Scanner.ScanInterval
	if oldInterval != newInterval {
		if s.ticker != nil {
			s.ticker.Reset(newInterval)
		}

		legacy.L.WithFields(logrus.Fields{
			"key":  "scanner.scan_interval",
			"from": oldInterval.String(),
			"to":   newInterval.String(),
		}).Info("Configuration changed")
	}

	legacy.L.Info("Detection rules refreshed")
	metrics.RulesetRevision.Set(float64(s.processor.RulesetRevision()))

	legacy.L.Info("Configuration hot-reloaded successfully")
	return nil
}

// UpdateConfig is the file-watcher callback. Failed updates keep the last
// valid configuration active.
func (s *Scanner) UpdateConfig(newConfig *models.Config) {
	if err := s.ApplyConfig(newConfig); err != nil {
		legacy.L.WithError(err).Error("Configuration update rejected; keeping the last valid configuration")
	}
}

// Start initializes and starts the scanner
func (s *Scanner) Start(ctx context.Context) error {
	// Start metrics server
	if s.metricsSrv != nil {
		go func() {
			if err := s.metricsSrv.StartWithRetry(ctx, 3, 5*time.Second); err != nil {
				legacy.L.WithError(err).Error("Failed to start metrics server")
			}
		}()
	}

	// Start metrics collector
	if s.metrics != nil {
		go s.metrics.StartMetricsUpdater(ctx, 30*time.Second)

		s.metrics.RecordScanStart()
	}

	s.mu.Lock()
	initialInterval := s.config.Scanner.ScanInterval
	s.ticker = time.NewTicker(initialInterval)
	s.mu.Unlock()

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName = "unknown"
	}

	legacy.L.WithFields(logrus.Fields{
		"node":     nodeName,
		"interval": initialInterval.String(),
	}).Info("ProcScan process scanner started")

	return s.runScanLoop(ctx)
}

func (s *Scanner) runScanLoop(ctx context.Context) error {
	defer s.ticker.Stop()
	defer func() {
		if s.metrics != nil {
			metrics.ScannerRunning.Set(0)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			legacy.L.Info("Scanner stopped")

			if s.metricsSrv != nil {
				if err := s.metricsSrv.Stop(ctx); err != nil {
					legacy.L.WithError(err).Warn("Failed to stop metrics server")
				}
			}

			return ctx.Err()
		case <-s.ticker.C:
			scanStart := time.Now()
			if err := s.scanProcesses(); err != nil {
				legacy.L.WithError(err).Error("Failed to scan processes")

				if s.metrics != nil {
					s.metrics.RecordScanError()
				}
			} else if s.metrics != nil {
				s.metrics.RecordScanComplete(time.Since(scanStart))
			}
		}
	}
}

func (s *Scanner) scanProcesses() error {
	legacy.L.Info("Starting new scan round...")

	s.mu.RLock()
	currentConfig := s.config
	s.mu.RUnlock()

	pids, err := s.processor.GetAllProcesses()
	if err != nil {
		return err
	}

	legacy.L.WithField("count", len(pids)).Info("Starting process analysis...")

	// Record number of processes to analyze
	if s.metrics != nil {
		s.metrics.RecordProcessesAnalyzed(len(pids))
	}

	numWorkers := runtime.NumCPU()
	pidChan := make(chan int, len(pids))
	resultsChan := make(chan *models.ProcessInfo, len(pids))

	var wg sync.WaitGroup

	for range numWorkers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for pid := range pidChan {
				processInfo, _ := s.processor.AnalyzeProcess(pid)
				if processInfo != nil {
					resultsChan <- processInfo
				}
			}
		}()
	}

	for _, pid := range pids {
		pidChan <- pid
	}

	close(pidChan)

	wg.Wait()
	close(resultsChan)
	legacy.L.Info("All process analysis completed")

	resultsByNamespace := make(map[string][]*models.ProcessInfo)
	for processInfo := range resultsChan {
		resultsByNamespace[processInfo.Namespace] = append(
			resultsByNamespace[processInfo.Namespace],
			processInfo,
		)
	}

	if len(resultsByNamespace) == 0 {
		legacy.L.Info("Scan round found 0 suspicious processes")
		return nil
	}

	// Record suspicious process metrics
	if s.metrics != nil {
		for namespace, processInfos := range resultsByNamespace {
			s.metrics.RecordSuspiciousProcesses(len(processInfos), namespace)
		}
	}

	legacy.L.WithFields(logrus.Fields{
		"namespaces_with_violations": len(resultsByNamespace),
	}).Info("Found suspicious processes, starting grouped processing...")

	finalResults := make([]*alert.NamespaceScanResult, 0, len(resultsByNamespace))
	for namespace, processInfos := range resultsByNamespace {
		s.reportProcscanViolations(processInfos)

		finalResults = append(finalResults, &alert.NamespaceScanResult{
			Namespace:    namespace,
			ProcessInfos: processInfos,
		})
	}

	if len(finalResults) > 0 {
		if err := alert.SendGlobalBatchAlert(
			finalResults,
			currentConfig.Notifications.Lark.Webhook,
			currentConfig.Notifications.Region,
		); err != nil {
			legacy.L.WithError(err).Error("Failed to send global batch Lark alert")
		}
	}

	legacy.L.Info("Scan round completed")

	return nil
}
