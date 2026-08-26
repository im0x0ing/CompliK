package procscanviolation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
	"sealos-complik-admin/internal/modules/autoban"
	"sealos-complik-admin/internal/modules/procscanrule"
	"sealos-complik-admin/internal/modules/projectconfig"
)

type fakeRuleRepository struct {
	configs map[string]*projectconfig.ProjectConfig
}

func (r *fakeRuleRepository) GetProjectConfigByName(
	_ context.Context,
	name string,
) (*projectconfig.ProjectConfig, error) {
	config := r.configs[name]
	if config == nil {
		return nil, gorm.ErrRecordNotFound
	}
	copy := *config
	return &copy, nil
}

func (r *fakeRuleRepository) CreateProjectConfig(
	_ context.Context,
	config *projectconfig.ProjectConfig,
) error {
	r.configs[config.ConfigName] = config
	return nil
}

func (r *fakeRuleRepository) UpdateProjectConfig(
	_ context.Context,
	config *projectconfig.ProjectConfig,
) error {
	r.configs[config.ConfigName] = config
	return nil
}

func (r *fakeRuleRepository) ListProjectConfigsByType(
	_ context.Context,
	_ string,
) ([]projectconfig.ProjectConfig, error) {
	return []projectconfig.ProjectConfig{}, nil
}

func (r *fakeRuleRepository) UpdateRuleSetAtomically(
	_ context.Context,
	_ uint64,
	_ procscanrule.RuleSet,
	_ procscanrule.LegacyRuleSet,
) error {
	return errors.New("not implemented")
}

type fakeDecisionHandler struct {
	calls []autoban.Violation
}

type fakeAttributionVerifier struct{}

func (fakeAttributionVerifier) VerifyContainer(
	context.Context,
	string,
	string,
	string,
	string,
	string,
) error {
	return nil
}

type failingAttributionVerifier struct{}

func (failingAttributionVerifier) VerifyContainer(
	context.Context,
	string,
	string,
	string,
	string,
	string,
) error {
	return errors.New("pod attribution mismatch")
}

type retryableAttributionVerifier struct{}

func (retryableAttributionVerifier) VerifyContainer(
	context.Context,
	string,
	string,
	string,
	string,
	string,
) error {
	return retryableVerificationError{}
}

type retryableVerificationError struct{}

func (retryableVerificationError) Error() string {
	return "kubernetes API unavailable"
}

func (retryableVerificationError) Retryable() bool {
	return true
}

func (h *fakeDecisionHandler) HandleViolationDecision(
	_ context.Context,
	violation autoban.Violation,
) (autoban.DecisionResult, error) {
	h.calls = append(h.calls, violation)
	return autoban.DecisionResult{
		Status: autoban.DecisionSubmitted,
		Reason: "ban_submission_succeeded",
	}, nil
}

func TestNormalizeViolationTreatsUnknownNamespaceAsUnresolved(t *testing.T) {
	unknown := "unknown"
	input, err := normalizeViolationInput(CreateViolationRequest{
		Namespace:      &unknown,
		PID:            10,
		ProcessName:    "xmrig",
		ProcessCommand: "xmrig --url pool",
		Message:        "matched",
		DetectedAt:     testDetectedAt(),
	})
	if err != nil {
		t.Fatalf("normalizeViolationInput() error = %v", err)
	}
	if input.Namespace != nil || input.AttributionStatus != "unresolved" {
		t.Fatalf("unexpected attribution: namespace=%v status=%q", input.Namespace, input.AttributionStatus)
	}
}

func TestValidateAndHandleAutobanRejectsUnresolvedAndStaleEvents(t *testing.T) {
	ruleService := newRuleService(t)
	handler := &fakeDecisionHandler{}
	service := &Service{
		rules:               ruleService,
		autoban:             handler,
		attributionVerifier: fakeAttributionVerifier{},
	}

	unresolved := &normalizedViolationInput{AttributionStatus: "unresolved"}
	decision := service.validateAndHandleAutoban(context.Background(), unresolved, &ProcscanViolationEvent{})
	if decision.Reason != "unresolved_attribution" {
		t.Fatalf("unresolved decision = %+v", decision)
	}

	namespace := "demo"
	stale := validInput(namespace)
	stale.RulesetRevision = 6
	decision = service.validateAndHandleAutoban(context.Background(), stale, eventFromInput(stale))
	if decision.Reason != "stale_ruleset_revision" {
		t.Fatalf("stale decision = %+v", decision)
	}
	if len(handler.calls) != 0 {
		t.Fatalf("ineligible events reached autoban: %+v", handler.calls)
	}
}

func TestValidateAndHandleAutobanSubmitsCurrentValidatedBanRule(t *testing.T) {
	ruleService := newRuleService(t)
	handler := &fakeDecisionHandler{}
	service := &Service{
		rules:               ruleService,
		autoban:             handler,
		attributionVerifier: fakeAttributionVerifier{},
	}

	input := validInput("demo")
	decision := service.validateAndHandleAutoban(
		context.Background(),
		input,
		eventFromInput(input),
	)
	if decision.Status != autoban.DecisionSubmitted {
		t.Fatalf("eligible decision = %+v", decision)
	}
	if len(handler.calls) != 1 || !handler.calls[0].RuleValidated {
		t.Fatalf("validated event was not submitted once: %+v", handler.calls)
	}
}

func TestValidateAndHandleAutobanRejectsFailedAttributionVerification(t *testing.T) {
	ruleService := newRuleService(t)
	handler := &fakeDecisionHandler{}
	service := &Service{
		rules:               ruleService,
		autoban:             handler,
		attributionVerifier: failingAttributionVerifier{},
	}

	input := validInput("demo")
	decision := service.validateAndHandleAutoban(
		context.Background(),
		input,
		eventFromInput(input),
	)
	if decision.Reason != "attribution_verification_failed" {
		t.Fatalf("decision = %+v, want attribution verification failure", decision)
	}
	if len(handler.calls) != 0 {
		t.Fatalf("failed attribution reached autoban: %+v", handler.calls)
	}
}

func TestValidateAndHandleAutobanRetriesTransientAttributionFailure(t *testing.T) {
	ruleService := newRuleService(t)
	handler := &fakeDecisionHandler{}
	service := &Service{
		rules:               ruleService,
		autoban:             handler,
		attributionVerifier: retryableAttributionVerifier{},
	}

	input := validInput("demo")
	decision := service.validateAndHandleAutoban(
		context.Background(),
		input,
		eventFromInput(input),
	)
	if decision.Status != autoban.DecisionFailed ||
		decision.Reason != "attribution_verification_failed" {
		t.Fatalf("decision = %+v, want retryable attribution failure", decision)
	}
}

func TestNormalizeEventIDIncludesPodUID(t *testing.T) {
	namespace := "demo"
	req := CreateViolationRequest{
		Namespace:      &namespace,
		PodName:        "miner-pod",
		PodUID:         "pod-a",
		ContainerID:    "container",
		NodeName:       "node-a",
		PID:            42,
		ProcessName:    "xmrig",
		ProcessCommand: "xmrig --url pool",
		Message:        "matched",
		DetectedAt:     testDetectedAt(),
	}
	first, err := normalizeViolationInput(req)
	if err != nil {
		t.Fatalf("normalize first input: %v", err)
	}

	req.PodUID = "pod-b"
	second, err := normalizeViolationInput(req)
	if err != nil {
		t.Fatalf("normalize second input: %v", err)
	}
	if first.EventID == second.EventID {
		t.Fatal("event ID did not change when Pod UID changed")
	}
}

func TestShouldRetryAutobanOnlyForUnevaluatedOrFailedEvents(t *testing.T) {
	tests := []struct {
		name   string
		status string
		reason string
		want   bool
	}{
		{name: "empty status", want: true},
		{name: "initial decision", status: autoban.DecisionNotTriggered, reason: "not_evaluated", want: true},
		{name: "failed decision", status: autoban.DecisionFailed, reason: "ban_submission_failed", want: true},
		{name: "submitted", status: autoban.DecisionSubmitted, reason: "ban_submission_succeeded"},
		{name: "dry run", status: autoban.DecisionDryRun, reason: "policy_dry_run"},
		{name: "policy rejected", status: autoban.DecisionNotTriggered, reason: "policy_disabled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldRetryAutoban(&ProcscanViolationEvent{
				AutobanStatus: tt.status,
				AutobanReason: tt.reason,
			}, time.Now().UTC())
			if got != tt.want {
				t.Fatalf("shouldRetryAutoban() = %v, want %v", got, tt.want)
			}
		})
	}
}

func newRuleService(t *testing.T) *procscanrule.Service {
	t.Helper()
	rules := procscanrule.RuleSet{
		SchemaVersion:   2,
		RulesetRevision: 7,
		Rules: []procscanrule.Rule{{
			ID: "miner-xmrig", Name: "XMRig", Enabled: true,
			MatchType: procscanrule.MatchTypeProcessName,
			Pattern:   "(?i)^xmrig$",
			Severity:  procscanrule.SeverityCritical,
			Action:    procscanrule.ActionBan,
		}},
	}
	data, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules: %v", err)
	}
	repository := &fakeRuleRepository{configs: map[string]*projectconfig.ProjectConfig{
		procscanrule.V2ConfigName: {
			ConfigName:  procscanrule.V2ConfigName,
			ConfigType:  procscanrule.V2ConfigType,
			ConfigValue: data,
		},
	}}
	return procscanrule.NewService(repository, false)
}

func validInput(namespace string) *normalizedViolationInput {
	return &normalizedViolationInput{
		Namespace:         &namespace,
		PodName:           "miner-pod",
		PodUID:            "pod-uid",
		ContainerID:       "container-id",
		NodeName:          "node-a",
		ProcessName:       "xmrig",
		ProcessCommand:    "xmrig --url pool",
		MatchType:         string(procscanrule.MatchTypeProcessName),
		MatchRule:         "(?i)^xmrig$",
		RulesetRevision:   7,
		PrimaryRuleID:     "miner-xmrig",
		MatchedRuleIDs:    []string{"miner-xmrig"},
		Severity:          string(procscanrule.SeverityCritical),
		RuleAction:        string(procscanrule.ActionBan),
		AttributionStatus: "resolved",
		IsIllegal:         true,
		DetectedAt:        testDetectedAt(),
	}
}

func eventFromInput(input *normalizedViolationInput) *ProcscanViolationEvent {
	return &ProcscanViolationEvent{
		Namespace:       input.Namespace,
		PodName:         input.PodName,
		ProcessName:     input.ProcessName,
		ProcessCommand:  input.ProcessCommand,
		PrimaryRuleID:   input.PrimaryRuleID,
		RulesetRevision: input.RulesetRevision,
		Message:         "matched",
		IsIllegal:       input.IsIllegal,
		DetectedAt:      input.DetectedAt,
	}
}

func testDetectedAt() time.Time {
	return time.Date(2026, time.August, 13, 10, 0, 0, 0, time.UTC)
}
//nolint:testpackage // Tests set unexported service clock and inspect unexported model fields.
