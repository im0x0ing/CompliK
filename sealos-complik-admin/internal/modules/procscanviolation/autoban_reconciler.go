package procscanviolation

import (
	"context"
	"errors"
	"log"
	"time"

	"gorm.io/gorm"
)

const (
	defaultAutobanRetryReconcileInterval = 30 * time.Second
	defaultAutobanRetryReconcileLimit    = 50
)

func (s *Service) StartAutobanRetryReconciler(ctx context.Context, interval time.Duration) {
	if s == nil {
		return
	}
	if interval <= 0 {
		interval = defaultAutobanRetryReconcileInterval
	}

	s.autobanReconcileOnce.Do(func() {
		go s.runAutobanRetryReconciler(ctx, interval)
	})
}

func (s *Service) runAutobanRetryReconciler(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if err := s.ReconcilePendingAutobans(ctx, defaultAutobanRetryReconcileLimit); err != nil {
		log.Printf("procscan autoban retry reconciler: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.ReconcilePendingAutobans(ctx, defaultAutobanRetryReconcileLimit); err != nil {
				log.Printf("procscan autoban retry reconciler: %v", err)
			}
		}
	}
}

func (s *Service) ReconcilePendingAutobans(ctx context.Context, limit int) error {
	if s == nil || s.repository == nil {
		return nil
	}

	now := s.now().UTC()
	candidates, err := s.repository.ListAutobanRetryCandidates(ctx, now, limit)
	if err != nil {
		return err
	}

	var errs []error
	for i := range candidates {
		eventID := stringValue(candidates[i].EventID)
		if eventID == "" {
			continue
		}
		if err := s.processAutobanUnderEventLock(ctx, eventID); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (s *Service) processAutobanUnderEventLock(ctx context.Context, eventID string) error {
	return s.repository.WithEventIDLock(ctx, eventID, func(tx *gorm.DB, locked *ProcscanViolationEvent) error {
		now := s.now().UTC()
		if !shouldRetryAutoban(locked, now) {
			return nil
		}

		input := normalizedInputFromEvent(locked)
		decision := s.validateAndHandleAutoban(ctx, input, locked)
		attemptCount := locked.AutobanAttemptCount + 1

		var nextRetryAt *time.Time
		if shouldScheduleAutobanRetry(decision, attemptCount) {
			retryAt := now.Add(autobanRetryDelay(attemptCount))
			nextRetryAt = &retryAt
		}

		updated, err := s.repository.UpdateAutobanDecisionIfAttempt(
			ctx,
			tx,
			locked.ID,
			decision.Status,
			decision.Reason,
			attemptCount,
			nextRetryAt,
			locked.AutobanAttemptCount,
		)
		if err != nil {
			return err
		}
		if !updated {
			return nil
		}

		return nil
	})
}
