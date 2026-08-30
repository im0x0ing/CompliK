package procscanviolation

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"slices"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"
	"sealos-complik-admin/internal/modules/autoban"
	"sealos-complik-admin/internal/modules/pagequery"
	"sealos-complik-admin/internal/modules/procscanrule"
	"sealos-complik-admin/internal/modules/violationquery"
)

var (
	ErrViolationInvalidInput = errors.New(
		"pid, process name, process command, message, and detected time are required",
	)
	ErrViolationNotFound = errors.New("procscan violation not found")
)

const (
	maxMatchedRuleIDs = 64
	maxRawPayloadSize = 64 << 10
)

type AttributionVerifier interface {
	VerifyContainer(
		ctx context.Context,
		namespace string,
		podName string,
		podUID string,
		containerID string,
		nodeName string,
	) error
}

type Service struct {
	repository          *Repository
	autoban             autoban.DecisionHandler
	rules               *procscanrule.Service
	attributionVerifier AttributionVerifier
	now                 func() time.Time
}

func NewService(
	repository *Repository,
	autobanHandler autoban.DecisionHandler,
	ruleService *procscanrule.Service,
	verifier ...AttributionVerifier,
) *Service {
	var attributionVerifier AttributionVerifier
	if len(verifier) > 0 {
		attributionVerifier = verifier[0]
	}
	return &Service{
		repository:          repository,
		autoban:             autobanHandler,
		rules:               ruleService,
		attributionVerifier: attributionVerifier,
		now:                 time.Now,
	}
}

func (s *Service) CreateViolation(ctx context.Context, req CreateViolationRequest) error {
	input, err := normalizeViolationInput(req)
	if err != nil {
		return err
	}

	rawPayloadJSON, err := marshalRawPayload(input.RawPayload)
	if err != nil {
		return err
	}
	matchedRuleIDsJSON, err := marshalStringSlice(input.MatchedRuleIDs)
	if err != nil {
		return err
	}

	violation := &ProcscanViolationEvent{
		EventID:           stringPointer(input.EventID),
		Namespace:         input.Namespace,
		PodName:           input.PodName,
		PodUID:            input.PodUID,
		ContainerID:       input.ContainerID,
		NodeName:          input.NodeName,
		PID:               input.PID,
		ProcessName:       input.ProcessName,
		ProcessCommand:    input.ProcessCommand,
		MatchType:         input.MatchType,
		MatchRule:         input.MatchRule,
		RulesetRevision:   input.RulesetRevision,
		PrimaryRuleID:     input.PrimaryRuleID,
		MatchedRuleIDs:    matchedRuleIDsJSON,
		Severity:          input.Severity,
		RuleAction:        input.RuleAction,
		AttributionStatus: input.AttributionStatus,
		AttributionReason: input.AttributionReason,
		AutobanStatus:     autoban.DecisionNotTriggered,
		AutobanReason:     "not_evaluated",
		Message:           input.Message,
		IsIllegal:         input.IsIllegal,
		LabelActionStatus: input.LabelActionStatus,
		LabelActionResult: input.LabelActionResult,
		DetectedAt:        input.DetectedAt,
		RawPayload:        rawPayloadJSON,
	}

	created, err := s.repository.CreateViolation(ctx, violation)
	if err != nil {
		return translateRepositoryError(err)
	}
	if !created {
		existing, err := s.repository.GetViolationByEventID(ctx, input.EventID)
		if err != nil {
			return translateRepositoryError(err)
		}
		if !shouldRetryAutoban(existing, s.now().UTC()) {
			return nil
		}
		violation = existing
		input = normalizedInputFromEvent(existing)
	}

	decision := s.validateAndHandleAutoban(ctx, input, violation)
	attemptCount := violation.AutobanAttemptCount + 1
	var nextRetryAt *time.Time
	if shouldScheduleAutobanRetry(decision, attemptCount) {
		retryAt := s.now().UTC().Add(autobanRetryDelay(attemptCount))
		nextRetryAt = &retryAt
	}

	violation.AutobanStatus = decision.Status
	violation.AutobanReason = decision.Reason
	if err := s.repository.UpdateAutobanDecision(
		ctx,
		violation.ID,
		decision.Status,
		decision.Reason,
		attemptCount,
		nextRetryAt,
	); err != nil {
		return translateRepositoryError(err)
	}

	return nil
}

func (s *Service) validateAndHandleAutoban(
	ctx context.Context,
	input *normalizedViolationInput,
	violation *ProcscanViolationEvent,
) autoban.DecisionResult {
	if input.AttributionStatus != "resolved" || input.Namespace == nil {
		return autoban.DecisionResult{Status: autoban.DecisionNotTriggered, Reason: "unresolved_attribution"}
	}
	if input.PodUID == "" || s.attributionVerifier == nil {
		return autoban.DecisionResult{
			Status: autoban.DecisionNotTriggered,
			Reason: "attribution_not_verified",
		}
	}
	if err := s.attributionVerifier.VerifyContainer(
		ctx,
		*input.Namespace,
		input.PodName,
		input.PodUID,
		input.ContainerID,
		input.NodeName,
	); err != nil {
		log.Printf(
			"procscan attribution verification failed for %s/%s: %v",
			*input.Namespace,
			input.PodName,
			err,
		)
		var retryable interface{ Retryable() bool }
		if errors.As(err, &retryable) && retryable.Retryable() {
			return autoban.DecisionResult{
				Status: autoban.DecisionFailed,
				Reason: "attribution_verification_failed",
			}
		}
		return autoban.DecisionResult{
			Status: autoban.DecisionNotTriggered,
			Reason: "attribution_verification_failed",
		}
	}
	if s.rules == nil {
		return autoban.DecisionResult{Status: autoban.DecisionFailed, Reason: "rule_service_unavailable"}
	}

	validation, err := s.rules.ValidateViolation(ctx, procscanrule.ViolationCandidate{
		RulesetRevision: input.RulesetRevision,
		PrimaryRuleID:   input.PrimaryRuleID,
		MatchedRuleIDs:  input.MatchedRuleIDs,
		MatchType:       procscanrule.MatchType(input.MatchType),
		MatchRule:       input.MatchRule,
		Severity:        procscanrule.Severity(input.Severity),
		RuleAction:      procscanrule.Action(input.RuleAction),
		Sample: procscanrule.ProcessSample{
			ProcessName: input.ProcessName,
			Command:     input.ProcessCommand,
			Namespace:   *input.Namespace,
			PodName:     input.PodName,
		},
	})
	if err != nil {
		log.Printf("procscan rule validation failed: %v", err)
		return autoban.DecisionResult{Status: autoban.DecisionFailed, Reason: "rule_validation_failed"}
	}
	if !validation.Eligible {
		return autoban.DecisionResult{Status: autoban.DecisionNotTriggered, Reason: validation.Reason}
	}
	if s.autoban == nil {
		return autoban.DecisionResult{Status: autoban.DecisionNotTriggered, Reason: "autoban_handler_unavailable"}
	}

	decision, err := s.autoban.HandleViolationDecision(ctx, autoban.Violation{
		Namespace:    *violation.Namespace,
		Source:       autoban.SourceProcscan,
		DetectorName: violation.PrimaryRuleID,
		ProcessName:  violation.ProcessName,
		Summary:      violation.Message,
		Detail: strings.TrimSpace(strings.Join([]string{
			"process_name=" + violation.ProcessName,
			"process_command=" + violation.ProcessCommand,
			"pod_name=" + violation.PodName,
			"node_name=" + violation.NodeName,
			"primary_rule_id=" + violation.PrimaryRuleID,
			"ruleset_revision=" + strconv.FormatUint(violation.RulesetRevision, 10),
		}, "\n")),
		IsIllegal:     isEffectiveViolation(violation),
		DetectedAt:    violation.DetectedAt,
		RuleValidated: true,
	})
	if err != nil {
		log.Printf("procscan autoban failed for %s: %v", *violation.Namespace, err)
	}
	return decision
}

func (s *Service) DeleteViolations(ctx context.Context, namespace string) error {
	if err := validateNamespace(namespace); err != nil {
		return err
	}

	if err := s.repository.DeleteViolationsByNamespace(ctx, namespace); err != nil {
		return translateRepositoryError(err)
	}

	return nil
}

func (s *Service) DeleteViolationByID(ctx context.Context, id uint64) error {
	if id == 0 {
		return ErrViolationInvalidInput
	}

	if err := s.repository.DeleteViolationByID(ctx, id); err != nil {
		return translateRepositoryError(err)
	}

	return nil
}

func (s *Service) GetViolations(
	ctx context.Context,
	namespace string,
	includeAll bool,
) ([]ViolationResponse, error) {
	if err := validateNamespace(namespace); err != nil {
		return nil, err
	}

	violations, err := s.repository.GetViolationsByNamespace(ctx, namespace, includeAll)
	if err != nil {
		return nil, translateRepositoryError(err)
	}

	responses := make([]ViolationResponse, 0, len(violations))
	for i := range violations {
		responses = append(responses, *toViolationResponse(&violations[i]))
	}

	return responses, nil
}

func (s *Service) ListViolations(
	ctx context.Context,
	includeAll bool,
) ([]ViolationResponse, error) {
	violations, err := s.repository.ListViolations(ctx, includeAll)
	if err != nil {
		return nil, err
	}

	responses := make([]ViolationResponse, 0, len(violations))
	for i := range violations {
		responses = append(responses, *toViolationResponse(&violations[i]))
	}

	return responses, nil
}

func (s *Service) ListViolationsPage(
	ctx context.Context,
	options violationquery.ListOptions,
) (*PaginatedViolationResponse, error) {
	violations, total, err := s.repository.ListViolationsPage(ctx, options)
	if err != nil {
		return nil, translateRepositoryError(err)
	}

	responses := make([]ViolationResponse, 0, len(violations))
	for i := range violations {
		responses = append(responses, *toViolationResponse(&violations[i]))
	}

	response := pagequery.NewPaginatedResponse(responses, total, options.Options)

	return &response, nil
}

func (s *Service) GetViolationStatus(
	ctx context.Context,
	namespace string,
) (*ViolationStatusResponse, error) {
	if err := validateNamespace(namespace); err != nil {
		return nil, err
	}

	violations, err := s.repository.GetViolationsByNamespace(ctx, namespace, false)
	if err != nil {
		if errors.Is(translateRepositoryError(err), ErrViolationNotFound) {
			return &ViolationStatusResponse{Violated: false}, nil
		}
		return nil, err
	}

	return &ViolationStatusResponse{Violated: len(violations) > 0}, nil
}

type normalizedViolationInput struct {
	EventID           string
	Namespace         *string
	PodName           string
	PodUID            string
	ContainerID       string
	NodeName          string
	PID               int
	ProcessName       string
	ProcessCommand    string
	MatchType         string
	MatchRule         string
	RulesetRevision   uint64
	PrimaryRuleID     string
	MatchedRuleIDs    []string
	Severity          string
	RuleAction        string
	AttributionStatus string
	AttributionReason string
	Message           string
	IsIllegal         bool
	LabelActionStatus string
	LabelActionResult string
	DetectedAt        time.Time
	RawPayload        json.RawMessage
}

func normalizeViolationInput(req CreateViolationRequest) (*normalizedViolationInput, error) {
	if len(req.RawPayload) > maxRawPayloadSize ||
		len(req.MatchedRuleIDs) > maxMatchedRuleIDs {
		return nil, ErrViolationInvalidInput
	}
	if len(req.EventID) > 64 ||
		(req.Namespace != nil && len(strings.TrimSpace(*req.Namespace)) > 255) ||
		len(req.PodName) > 255 ||
		len(req.PodUID) > 128 ||
		len(req.ContainerID) > 128 ||
		len(req.NodeName) > 128 ||
		len(req.ProcessName) > 255 ||
		len(req.ProcessCommand) > 4096 ||
		len(req.MatchType) > 32 ||
		len(req.MatchRule) > 1024 ||
		len(req.PrimaryRuleID) > 255 ||
		len(req.Severity) > 16 ||
		len(req.RuleAction) > 16 ||
		len(req.AttributionStatus) > 32 ||
		len(req.AttributionReason) > 255 ||
		len(req.Message) > 4096 ||
		len(req.LabelActionStatus) > 32 ||
		len(req.LabelActionResult) > 4096 {
		return nil, ErrViolationInvalidInput
	}
	for _, ruleID := range req.MatchedRuleIDs {
		if len(strings.TrimSpace(ruleID)) > 255 {
			return nil, ErrViolationInvalidInput
		}
	}

	var namespace *string
	if req.Namespace != nil {
		trimmed := strings.TrimSpace(*req.Namespace)
		if trimmed != "" && !strings.EqualFold(trimmed, "unknown") {
			namespace = &trimmed
		}
	}
	trimmedProcessName := strings.TrimSpace(req.ProcessName)
	trimmedProcessCommand := strings.TrimSpace(req.ProcessCommand)
	trimmedMessage := strings.TrimSpace(req.Message)

	if req.PID <= 0 || trimmedProcessName == "" ||
		trimmedProcessCommand == "" ||
		trimmedMessage == "" ||
		req.DetectedAt.IsZero() {
		return nil, ErrViolationInvalidInput
	}

	isIllegal := true
	if req.IsIllegal != nil {
		isIllegal = *req.IsIllegal
	}

	attributionStatus, err := normalizeAttributionStatus(req.AttributionStatus, namespace)
	if err != nil {
		return nil, err
	}

	eventID, err := requireEventID(req.EventID)
	if err != nil {
		return nil, err
	}

	return &normalizedViolationInput{
		EventID:           eventID,
		Namespace:         namespace,
		PodName:           strings.TrimSpace(req.PodName),
		PodUID:            strings.TrimSpace(req.PodUID),
		ContainerID:       strings.TrimSpace(req.ContainerID),
		NodeName:          strings.TrimSpace(req.NodeName),
		PID:               req.PID,
		ProcessName:       trimmedProcessName,
		ProcessCommand:    trimmedProcessCommand,
		MatchType:         strings.TrimSpace(req.MatchType),
		MatchRule:         strings.TrimSpace(req.MatchRule),
		RulesetRevision:   req.RulesetRevision,
		PrimaryRuleID:     strings.TrimSpace(req.PrimaryRuleID),
		MatchedRuleIDs:    uniqueTrimmed(req.MatchedRuleIDs),
		Severity:          strings.TrimSpace(req.Severity),
		RuleAction:        strings.TrimSpace(req.RuleAction),
		AttributionStatus: attributionStatus,
		AttributionReason: strings.TrimSpace(req.AttributionReason),
		Message:           trimmedMessage,
		IsIllegal:         isIllegal,
		LabelActionStatus: strings.TrimSpace(req.LabelActionStatus),
		LabelActionResult: strings.TrimSpace(req.LabelActionResult),
		DetectedAt:        req.DetectedAt,
		RawPayload:        req.RawPayload,
	}, nil
}

func uniqueTrimmed(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !slices.Contains(result, value) {
			result = append(result, value)
		}
	}
	return result
}

func normalizedInputFromEvent(violation *ProcscanViolationEvent) *normalizedViolationInput {
	if violation == nil {
		return nil
	}

	attributionStatus, err := normalizeAttributionStatus(violation.AttributionStatus, violation.Namespace)
	if err != nil {
		attributionStatus = strings.TrimSpace(violation.AttributionStatus)
	}

	return &normalizedViolationInput{
		EventID:           stringValue(violation.EventID),
		Namespace:         violation.Namespace,
		PodName:           strings.TrimSpace(violation.PodName),
		PodUID:            strings.TrimSpace(violation.PodUID),
		ContainerID:       strings.TrimSpace(violation.ContainerID),
		NodeName:          strings.TrimSpace(violation.NodeName),
		PID:               violation.PID,
		ProcessName:       strings.TrimSpace(violation.ProcessName),
		ProcessCommand:    strings.TrimSpace(violation.ProcessCommand),
		MatchType:         strings.TrimSpace(violation.MatchType),
		MatchRule:         strings.TrimSpace(violation.MatchRule),
		RulesetRevision:   violation.RulesetRevision,
		PrimaryRuleID:     strings.TrimSpace(violation.PrimaryRuleID),
		MatchedRuleIDs:    parseStringSlice(violation.MatchedRuleIDs),
		Severity:          strings.TrimSpace(violation.Severity),
		RuleAction:        strings.TrimSpace(violation.RuleAction),
		AttributionStatus: attributionStatus,
		AttributionReason: strings.TrimSpace(violation.AttributionReason),
		Message:           strings.TrimSpace(violation.Message),
		IsIllegal:         violation.IsIllegal,
		LabelActionStatus: strings.TrimSpace(violation.LabelActionStatus),
		LabelActionResult: strings.TrimSpace(violation.LabelActionResult),
		DetectedAt:        violation.DetectedAt,
		RawPayload:        parseRawPayload(violation.RawPayload),
	}
}

func normalizeAttributionStatus(raw string, namespace *string) (string, error) {
	attributionStatus := strings.TrimSpace(raw)
	if attributionStatus == "" {
		if namespace == nil {
			attributionStatus = "unresolved"
		} else {
			attributionStatus = "resolved"
		}
	}
	if attributionStatus != "resolved" && attributionStatus != "unresolved" {
		return "", ErrViolationInvalidInput
	}
	if (attributionStatus == "resolved") != (namespace != nil) {
		return "", ErrViolationInvalidInput
	}

	return attributionStatus, nil
}

func requireEventID(value string) (string, error) {
	eventID := strings.TrimSpace(value)
	if eventID == "" {
		return "", ErrViolationInvalidInput
	}

	return eventID, nil
}

func validateNamespace(namespace string) error {
	if strings.TrimSpace(namespace) == "" {
		return ErrViolationInvalidInput
	}

	return nil
}

func translateRepositoryError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrViolationNotFound
	}

	return err
}

func marshalRawPayload(payload json.RawMessage) (*string, error) {
	if len(payload) == 0 {
		return nil, nil
	}

	if !json.Valid(payload) {
		return nil, ErrViolationInvalidInput
	}

	result := string(payload)

	return &result, nil
}

func marshalStringSlice(values []string) (*string, error) {
	data, err := json.Marshal(values)
	if err != nil {
		return nil, ErrViolationInvalidInput
	}
	value := string(data)
	return &value, nil
}

func parseStringSlice(raw *string) []string {
	if raw == nil || *raw == "" {
		return []string{}
	}
	values := []string{}
	if err := json.Unmarshal([]byte(*raw), &values); err != nil {
		return []string{}
	}
	return values
}

func parseRawPayload(raw *string) json.RawMessage {
	if raw == nil || *raw == "" {
		return nil
	}

	return json.RawMessage(*raw)
}

func isEffectiveViolation(violation *ProcscanViolationEvent) bool {
	if violation == nil {
		return false
	}

	return violation.IsIllegal
}

func toViolationResponse(violation *ProcscanViolationEvent) *ViolationResponse {
	return &ViolationResponse{
		ID:                violation.ID,
		EventID:           stringValue(violation.EventID),
		Namespace:         violation.Namespace,
		PodName:           violation.PodName,
		PodUID:            violation.PodUID,
		ContainerID:       violation.ContainerID,
		NodeName:          violation.NodeName,
		PID:               violation.PID,
		ProcessName:       violation.ProcessName,
		ProcessCommand:    violation.ProcessCommand,
		MatchType:         violation.MatchType,
		MatchRule:         violation.MatchRule,
		RulesetRevision:   violation.RulesetRevision,
		PrimaryRuleID:     violation.PrimaryRuleID,
		MatchedRuleIDs:    parseStringSlice(violation.MatchedRuleIDs),
		Severity:          violation.Severity,
		RuleAction:        violation.RuleAction,
		AttributionStatus: violation.AttributionStatus,
		AttributionReason: violation.AttributionReason,
		AutobanStatus:     violation.AutobanStatus,
		AutobanReason:     violation.AutobanReason,
		Message:           violation.Message,
		IsIllegal:         isEffectiveViolation(violation),
		LabelActionStatus: violation.LabelActionStatus,
		LabelActionResult: violation.LabelActionResult,
		DetectedAt:        violation.DetectedAt,
		RawPayload:        parseRawPayload(violation.RawPayload),
		CreatedAt:         violation.CreatedAt,
		UpdatedAt:         violation.UpdatedAt,
	}
}

func stringPointer(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return &value
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
