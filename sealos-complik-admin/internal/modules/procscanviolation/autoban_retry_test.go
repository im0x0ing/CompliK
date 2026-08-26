package procscanviolation

import (
	"testing"
	"time"

	"sealos-complik-admin/internal/modules/autoban"
)

func TestShouldRetryAutobanRespectsBackoffAndAttemptLimit(t *testing.T) {
	now := time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC)
	retryAt := now.Add(2 * time.Minute)
	violation := &ProcscanViolationEvent{
		AutobanStatus:       autoban.DecisionFailed,
		AutobanReason:       "ban_submission_failed",
		AutobanAttemptCount: 2,
		AutobanNextRetryAt:  &retryAt,
	}

	if shouldRetryAutoban(violation, now) {
		t.Fatal("expected backoff to block retry")
	}

	if !shouldRetryAutoban(violation, retryAt) {
		t.Fatal("expected retry after backoff window")
	}

	violation.AutobanAttemptCount = maxAutobanAttempts
	if shouldRetryAutoban(violation, retryAt.Add(time.Minute)) {
		t.Fatal("expected attempt limit to block retry")
	}
}

func TestShouldRetryAutobanSkipsPermanentReasons(t *testing.T) {
	now := time.Now().UTC()
	violation := &ProcscanViolationEvent{
		AutobanStatus: autoban.DecisionFailed,
		AutobanReason: "policy_scope_rejected",
	}
	if shouldRetryAutoban(violation, now) {
		t.Fatal("expected permanent failure to skip retry")
	}
}

func TestAutobanRetryDelayCapsAtEightMinutes(t *testing.T) {
	if got := autobanRetryDelay(1); got != 30*time.Second {
		t.Fatalf("attempt 1 delay = %v, want 30s", got)
	}
	if got := autobanRetryDelay(10); got != maxAutobanRetry {
		t.Fatalf("attempt 10 delay = %v, want cap %v", got, maxAutobanRetry)
	}
}
