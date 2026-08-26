package procscanrule

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"gorm.io/gorm"
	"sealos-complik-admin/internal/modules/projectconfig"
)

const (
	LegacyConfigName = "procscan_rules"
	LegacyConfigType = "procscan_rules"
	V2ConfigName     = "procscan_rules_v2"
	V2ConfigType     = "procscan_rules_v2"
	RuntimeConfigType = "procscan_notifications_runtime"
)

var (
	ErrInvalidRuleSet   = errors.New("invalid procscan ruleset")
	ErrRevisionConflict = errors.New("procscan ruleset revision conflict")
	ErrV2WritesDisabled = errors.New("procscan V2 rule writes are disabled")
)

type RuleSetUpdate struct {
	SchemaVersion int        `json:"schema_version"`
	Rules         []Rule     `json:"rules"`
	Exemptions    Exemptions `json:"exemptions"`
}

type Repository interface {
	GetProjectConfigByName(ctx context.Context, name string) (*projectconfig.ProjectConfig, error)
	CreateProjectConfig(ctx context.Context, config *projectconfig.ProjectConfig) error
	UpdateProjectConfig(ctx context.Context, config *projectconfig.ProjectConfig) error
	ListProjectConfigsByType(ctx context.Context, configType string) ([]projectconfig.ProjectConfig, error)
	UpdateRuleSetAtomically(
		ctx context.Context,
		expectedRevision uint64,
		next RuleSet,
		legacy LegacyRuleSet,
	) error
}

type RuntimeConfig struct {
	Region  string `json:"region"`
	Webhook string `json:"webhook"`
}

type Service struct {
	repository      Repository
	v2WritesEnabled bool
	cacheMu         sync.RWMutex
	cachedRevision  uint64
	cachedMatcher   *Matcher
}

func NewService(repository Repository, v2WritesEnabled bool) *Service {
	return &Service{repository: repository, v2WritesEnabled: v2WritesEnabled}
}

func (s *Service) V2WritesEnabled() bool {
	return s != nil && s.v2WritesEnabled
}

func (s *Service) GetRuleSet(ctx context.Context) (*RuleSet, error) {
	if s == nil || s.repository == nil {
		return nil, errors.New("procscan rule repository is required")
	}

	rules, err := s.readV2Config(ctx)
	if err == nil {
		return rules, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	legacy, legacyErr := s.readLegacyConfig(ctx)
	if legacyErr != nil && !errors.Is(legacyErr, gorm.ErrRecordNotFound) {
		return nil, legacyErr
	}
	migratedRules := ConvertLegacyRules(legacy)
	if validateErr := ValidateRuleSet(migratedRules); validateErr != nil {
		return nil, fmt.Errorf("%w: migrated V1 rules: %v", ErrInvalidRuleSet, validateErr)
	}
	if persistErr := s.saveConfig(ctx, V2ConfigName, V2ConfigType, migratedRules); persistErr != nil {
		// Another Admin replica may have completed the same first-read migration.
		// Prefer the now-persisted valid ruleset over returning a transient duplicate error.
		if migrated, readErr := s.readV2Config(ctx); readErr == nil {
			return migrated, nil
		}
		return nil, fmt.Errorf("persist migrated procscan V2 rules: %w", persistErr)
	}
	return &migratedRules, nil
}

func (s *Service) readV2Config(ctx context.Context) (*RuleSet, error) {
	config, err := s.repository.GetProjectConfigByName(ctx, V2ConfigName)
	if err != nil {
		return nil, err
	}
	var rules RuleSet
	if err := json.Unmarshal(config.ConfigValue, &rules); err != nil {
		return nil, fmt.Errorf("decode procscan V2 rules: %w", err)
	}
	if err := ValidateRuleSet(rules); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRuleSet, err)
	}
	return &rules, nil
}

func (s *Service) GetLegacyRuleSet(ctx context.Context) (*LegacyRuleSet, error) {
	legacy, err := s.readLegacyConfig(ctx)
	if err == nil {
		return &legacy, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	rules, rulesErr := s.GetRuleSet(ctx)
	if rulesErr != nil {
		return nil, rulesErr
	}
	projection := LegacyProjection(*rules)
	return &projection, nil
}

func (s *Service) GetRuntimeConfig(ctx context.Context) (*RuntimeConfig, error) {
	configs, err := s.repository.ListProjectConfigsByType(ctx, RuntimeConfigType)
	if err != nil {
		return nil, err
	}
	if len(configs) == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	var runtimeConfig RuntimeConfig
	if err := json.Unmarshal(configs[0].ConfigValue, &runtimeConfig); err != nil {
		return nil, fmt.Errorf("decode procscan runtime config: %w", err)
	}
	runtimeConfig.Region = strings.TrimSpace(runtimeConfig.Region)
	runtimeConfig.Webhook = strings.TrimSpace(runtimeConfig.Webhook)
	if runtimeConfig.Region == "" || runtimeConfig.Webhook == "" {
		return nil, errors.New("procscan runtime config requires region and webhook")
	}
	return &runtimeConfig, nil
}

func (s *Service) UpdateRuleSet(
	ctx context.Context,
	expectedRevision uint64,
	update RuleSetUpdate,
) (*RuleSet, error) {
	if !s.v2WritesEnabled {
		return nil, ErrV2WritesDisabled
	}
	current, err := s.GetRuleSet(ctx)
	if err != nil {
		return nil, err
	}
	if expectedRevision == 0 || expectedRevision != current.RulesetRevision {
		return nil, ErrRevisionConflict
	}

	next := RuleSet{
		SchemaVersion:   update.SchemaVersion,
		RulesetRevision: current.RulesetRevision + 1,
		Rules:           update.Rules,
		Exemptions:      update.Exemptions,
	}
	if err := ValidateRuleSet(next); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidRuleSet, err)
	}

	legacy := LegacyProjection(next)
	if err := s.repository.UpdateRuleSetAtomically(ctx, expectedRevision, next, legacy); err != nil {
		return nil, err
	}
	s.invalidateMatcherCache()
	return &next, nil
}

func (s *Service) ValidateUpdate(update RuleSetUpdate) error {
	rules := RuleSet{
		SchemaVersion:   update.SchemaVersion,
		RulesetRevision: 1,
		Rules:           update.Rules,
		Exemptions:      update.Exemptions,
	}
	if err := ValidateRuleSet(rules); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRuleSet, err)
	}
	return nil
}

func (s *Service) ValidateViolation(
	ctx context.Context,
	candidate ViolationCandidate,
) (ViolationValidation, error) {
	current, err := s.GetRuleSet(ctx)
	if err != nil {
		return ViolationValidation{}, err
	}
	if candidate.RulesetRevision == 0 {
		return ViolationValidation{Reason: "missing_ruleset_revision"}, nil
	}
	if candidate.RulesetRevision != current.RulesetRevision {
		return ViolationValidation{Reason: "stale_ruleset_revision"}, nil
	}

	matcher, err := s.compiledMatcher(*current)
	if err != nil {
		return ViolationValidation{}, fmt.Errorf("compile current procscan rules: %w", err)
	}
	match := matcher.Match(candidate.Sample)
	if match == nil {
		return ViolationValidation{Reason: "rule_mismatch"}, nil
	}
	primary := match.PrimaryRule
	reportedRuleMatches := candidate.PrimaryRuleID == primary.ID &&
		candidate.MatchType == primary.MatchType &&
		candidate.MatchRule == primary.Pattern &&
		candidate.Severity == primary.Severity &&
		candidate.RuleAction == primary.Action &&
		slices.Equal(candidate.MatchedRuleIDs, match.MatchedRuleIDs)
	if !reportedRuleMatches {
		return ViolationValidation{Reason: "rule_mismatch", Match: match}, nil
	}
	eligible := primary.Enabled && primary.MatchType == MatchTypeProcessName &&
		(primary.Severity == SeverityHigh || primary.Severity == SeverityCritical) &&
		primary.Action == ActionBan
	if !eligible {
		return ViolationValidation{Reason: "rule_not_eligible", Match: match}, nil
	}
	return ViolationValidation{Eligible: true, Reason: "eligible", Match: match}, nil
}

func (s *Service) compiledMatcher(rules RuleSet) (*Matcher, error) {
	s.cacheMu.RLock()
	if s.cachedMatcher != nil && s.cachedRevision == rules.RulesetRevision {
		matcher := s.cachedMatcher
		s.cacheMu.RUnlock()
		return matcher, nil
	}
	s.cacheMu.RUnlock()

	matcher, err := CompileRuleSet(rules)
	if err != nil {
		return nil, err
	}

	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if s.cachedMatcher != nil && s.cachedRevision == rules.RulesetRevision {
		return s.cachedMatcher, nil
	}
	s.cachedRevision = rules.RulesetRevision
	s.cachedMatcher = matcher
	return matcher, nil
}

func (s *Service) invalidateMatcherCache() {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	s.cachedRevision = 0
	s.cachedMatcher = nil
}

func (s *Service) readLegacyConfig(ctx context.Context) (LegacyRuleSet, error) {
	var legacy LegacyRuleSet
	config, err := s.repository.GetProjectConfigByName(ctx, LegacyConfigName)
	if err != nil {
		return legacy, err
	}
	if err := json.Unmarshal(config.ConfigValue, &legacy); err != nil {
		return legacy, fmt.Errorf("decode procscan V1 rules: %w", err)
	}
	return legacy, nil
}

func (s *Service) saveConfig(ctx context.Context, name, configType string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}

	config, err := s.repository.GetProjectConfigByName(ctx, name)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return s.repository.CreateProjectConfig(ctx, &projectconfig.ProjectConfig{
			ConfigName:  name,
			ConfigType:  configType,
			ConfigValue: data,
			Description: "Procscan detection rules managed by the dedicated rules API",
		})
	}
	if err != nil {
		return err
	}

	config.ConfigType = configType
	config.ConfigValue = data
	config.Description = strings.TrimSpace(config.Description)
	if config.Description == "" {
		config.Description = "Procscan detection rules managed by the dedicated rules API"
	}
	return s.repository.UpdateProjectConfig(ctx, config)
}
