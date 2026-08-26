package procscanviolation

import (
	"time"

	"sealos-complik-admin/internal/modules/autoban"
)

const (
	maxAutobanAttempts = 5
	baseAutobanRetry   = 30 * time.Second
	maxAutobanRetry    = 8 * time.Minute
)

func shouldRetryAutoban(violation *ProcscanViolationEvent, now time.Time) bool {
	if violation == nil {
		return false
	}
	if violation.AutobanAttemptCount >= maxAutobanAttempts {
		return false
	}
	if violation.AutobanNextRetryAt != nil && now.Before(violation.AutobanNextRetryAt.UTC()) {
		return false
	}

	switch violation.AutobanStatus {
	case "":
		return true
	case autoban.DecisionFailed:
		return !isPermanentAutobanReason(violation.AutobanReason)
	case autoban.DecisionNotTriggered:
		return violation.AutobanReason == "" || violation.AutobanReason == "not_evaluated"
	default:
		return false
	}
}

func shouldScheduleAutobanRetry(decision autoban.DecisionResult, attemptCount int) bool {
	if attemptCount >= maxAutobanAttempts {
		return false
	}
	if decision.Status != autoban.DecisionFailed {
		return false
	}
	return !isPermanentAutobanReason(decision.Reason)
}

func autobanRetryDelay(attemptCount int) time.Duration {
	if attemptCount <= 0 {
		return baseAutobanRetry
	}

	delay := baseAutobanRetry * time.Duration(1<<(attemptCount-1))
	if delay > maxAutobanRetry {
		return maxAutobanRetry
	}

	return delay
}

func isPermanentAutobanReason(reason string) bool {
	switch reason {
	case "policy_disabled",
		"policy_scope_rejected",
		"process_policy_rejected",
		"rule_mismatch",
		"rule_not_eligible",
		"stale_ruleset_revision",
		"unresolved_attribution",
		"attribution_not_verified",
		"not_an_effective_violation",
		"already_banned",
		"autoban_handler_unavailable",
		"rule_service_unavailable":
		return true
	default:
		return false
	}
}
