package autoban

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"sealos-complik-admin/internal/modules/ban"
)

type BanService interface {
	CreateBan(ctx context.Context, req ban.CreateBanRequest) error
	GetBanStatus(ctx context.Context, namespace string) (*ban.BanStatusResponse, error)
}

type idempotentBanService interface {
	CreateBanIfAbsent(ctx context.Context, req ban.CreateBanRequest) (bool, error)
}

type Service struct {
	policyRepository policyRepository
	banService       BanService
	now              func() time.Time
}

type Handler interface {
	HandleViolation(ctx context.Context, violation Violation) error
}

type DecisionHandler interface {
	HandleViolationDecision(ctx context.Context, violation Violation) (DecisionResult, error)
}

func NewService(policyRepository policyRepository, banService BanService) *Service {
	return &Service{
		policyRepository: policyRepository,
		banService:       banService,
		now:              time.Now,
	}
}

func (s *Service) HandleViolation(ctx context.Context, violation Violation) error {
	_, err := s.HandleViolationDecision(ctx, violation)
	return err
}

func (s *Service) HandleViolationDecision(
	ctx context.Context,
	violation Violation,
) (DecisionResult, error) {
	if s == nil || s.banService == nil {
		return DecisionResult{Status: DecisionFailed, Reason: "ban_service_unavailable"},
			errors.New("autoban ban service is unavailable")
	}

	if !violation.IsIllegal || violation.IsTest {
		return DecisionResult{Status: DecisionNotTriggered, Reason: "not_an_effective_violation"}, nil
	}

	policy := loadPolicy(ctx, s.policyRepository)
	if !policy.Enabled {
		return DecisionResult{Status: DecisionNotTriggered, Reason: "policy_disabled"}, nil
	}

	if !policy.allowsSource(violation.Source) || !policy.allowsNamespace(violation.Namespace) {
		return DecisionResult{Status: DecisionNotTriggered, Reason: "policy_scope_rejected"}, nil
	}

	if processName := strings.TrimSpace(violation.ProcessName); !violation.RuleValidated && processName != "" &&
		!policy.allowsProcessName(processName) {
		return DecisionResult{Status: DecisionNotTriggered, Reason: "process_policy_rejected"}, nil
	}

	if policy.DryRun {
		status, err := s.banService.GetBanStatus(ctx, strings.TrimSpace(violation.Namespace))
		if err != nil {
			log.Printf("autoban: failed to check active ban for %s: %v", violation.Namespace, err)
			return DecisionResult{Status: DecisionFailed, Reason: "ban_status_check_failed"}, err
		}
		if status != nil && status.Banned {
			return DecisionResult{Status: DecisionNotTriggered, Reason: "already_banned"}, nil
		}
		log.Printf(
			"autoban: dry-run would ban namespace %s from %s",
			violation.Namespace,
			violation.Source,
		)

		return DecisionResult{Status: DecisionDryRun, Reason: "policy_dry_run"}, nil
	}

	req := ban.CreateBanRequest{
		Namespace:    strings.TrimSpace(violation.Namespace),
		Reason:       s.buildReason(policy, violation),
		BanStartTime: s.now().UTC(),
		OperatorName: policy.OperatorName,
	}

	if idempotent, ok := s.banService.(idempotentBanService); ok {
		created, err := idempotent.CreateBanIfAbsent(ctx, req)
		if err != nil {
			log.Printf("autoban: failed to create ban for %s: %v", violation.Namespace, err)
			return DecisionResult{Status: DecisionFailed, Reason: "ban_submission_failed"}, err
		}
		if !created {
			return DecisionResult{Status: DecisionNotTriggered, Reason: "already_banned"}, nil
		}
		return DecisionResult{Status: DecisionSubmitted, Reason: "ban_submission_succeeded"}, nil
	}

	status, err := s.banService.GetBanStatus(ctx, strings.TrimSpace(violation.Namespace))
	if err != nil {
		log.Printf("autoban: failed to check active ban for %s: %v", violation.Namespace, err)
		return DecisionResult{Status: DecisionFailed, Reason: "ban_status_check_failed"}, err
	}
	if status != nil && status.Banned {
		return DecisionResult{Status: DecisionNotTriggered, Reason: "already_banned"}, nil
	}

	if err := s.banService.CreateBan(ctx, req); err != nil {
		log.Printf("autoban: failed to create ban for %s: %v", violation.Namespace, err)
		return DecisionResult{Status: DecisionFailed, Reason: "ban_submission_failed"}, err
	}

	return DecisionResult{Status: DecisionSubmitted, Reason: "ban_submission_succeeded"}, nil
}

func (s *Service) buildReason(policy Policy, violation Violation) string {
	var builder strings.Builder
	builder.WriteString(policy.ReasonPrefix)
	builder.WriteString(": ")
	builder.WriteString(string(violation.Source))
	builder.WriteString(" violation")

	if namespace := strings.TrimSpace(violation.Namespace); namespace != "" {
		builder.WriteString(" in ")
		builder.WriteString(namespace)
	}

	if detector := strings.TrimSpace(violation.DetectorName); detector != "" {
		builder.WriteString("\nDetector: ")
		builder.WriteString(detector)
	}

	if summary := strings.TrimSpace(violation.Summary); summary != "" {
		builder.WriteString("\nSummary: ")
		builder.WriteString(summary)
	}

	if detail := strings.TrimSpace(violation.Detail); detail != "" {
		builder.WriteString("\nDetail: ")
		builder.WriteString(detail)
	}

	if !violation.DetectedAt.IsZero() {
		builder.WriteString("\nDetected at: ")
		builder.WriteString(violation.DetectedAt.UTC().Format(time.RFC3339))
	}

	return builder.String()
}

func (s *Service) String() string {
	return fmt.Sprintf("autoban.Service<%p>", s)
}
