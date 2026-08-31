package procscanviolation

import (
	"testing"
	"time"

	"sealos-complik-admin/internal/modules/autoban"
)

func TestProcessAutobanUnderEventLockUsesRetryGate(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	retryAt := now.Add(time.Hour)
	violation := &ProcscanViolationEvent{
		EventID:             stringPointer("event-1"),
		AutobanStatus:       autoban.DecisionFailed,
		AutobanReason:       "ban_submission_failed",
		AutobanAttemptCount: 1,
		AutobanNextRetryAt:  &retryAt,
	}

	if shouldRetryAutoban(violation, now) {
		t.Fatal("shouldRetryAutoban() = true before next retry time")
	}
}
