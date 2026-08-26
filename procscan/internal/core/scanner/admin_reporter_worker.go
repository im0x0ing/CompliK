package scanner

import (
	"context"

	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
	legacy "github.com/bearslyricattack/CompliK/procscan/pkg/logger/legacy"
)

const (
	adminReportQueueSize = 256
	adminReportWorkers   = 2
)

func (s *Scanner) ensureAdminReporter(ctx context.Context) {
	if s == nil {
		return
	}

	s.reportMu.Lock()
	defer s.reportMu.Unlock()
	if s.reportStarted {
		return
	}
	if _, ok := s.adminEndpoint(); !ok {
		return
	}

	s.reportQueue = make(chan *models.ProcessInfo, adminReportQueueSize)
	s.reportStarted = true

	for range adminReportWorkers {
		go s.adminReportWorker(ctx)
	}
}

func (s *Scanner) adminReportWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case processInfo := <-s.reportQueue:
			if processInfo == nil {
				continue
			}

			endpoint, ok := s.adminEndpoint()
			if !ok {
				continue
			}

			if err := s.reportProcscanViolation(endpoint, processInfo); err != nil {
				legacy.L.WithFields(map[string]any{
					"namespace": processInfo.Namespace,
					"pod":       processInfo.PodName,
					"pid":       processInfo.PID,
					"error":     err.Error(),
				}).Error("Failed to report procscan violation to admin")
			}
		}
	}
}

func (s *Scanner) enqueueAdminReports(processInfos []*models.ProcessInfo) {
	if s == nil || len(processInfos) == 0 {
		return
	}

	s.reportMu.RLock()
	queue := s.reportQueue
	started := s.reportStarted
	s.reportMu.RUnlock()
	if !started || queue == nil {
		s.reportProcscanViolationsSync(processInfos)
		return
	}

	for _, processInfo := range processInfos {
		if processInfo == nil {
			continue
		}

		select {
		case queue <- processInfo:
		default:
			legacy.L.WithFields(map[string]any{
				"namespace": processInfo.Namespace,
				"pod":       processInfo.PodName,
				"pid":       processInfo.PID,
			}).Warn("Admin report queue is full, dropping procscan violation report")
		}
	}
}

func (s *Scanner) reportProcscanViolationsSync(processInfos []*models.ProcessInfo) {
	endpoint, ok := s.adminEndpoint()
	if !ok {
		legacy.L.Info("Admin reporting is disabled because notifications.admin.base_url is empty")
		return
	}

	for _, processInfo := range processInfos {
		if processInfo == nil {
			continue
		}

		if err := s.reportProcscanViolation(endpoint, processInfo); err != nil {
			legacy.L.WithFields(map[string]any{
				"namespace": processInfo.Namespace,
				"pod":       processInfo.PodName,
				"pid":       processInfo.PID,
				"error":     err.Error(),
			}).Error("Failed to report procscan violation to admin")
		}
	}
}

func (s *Scanner) stopAdminReporter() {
	s.reportMu.Lock()
	defer s.reportMu.Unlock()
	if !s.reportStarted || s.reportQueue == nil {
		return
	}

	close(s.reportQueue)
	s.reportQueue = nil
	s.reportStarted = false
}
