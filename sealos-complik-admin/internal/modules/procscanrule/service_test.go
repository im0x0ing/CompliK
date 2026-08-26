package procscanrule

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"gorm.io/gorm"
	"sealos-complik-admin/internal/modules/projectconfig"
)

type fakeRepository struct {
	configs map[string]*projectconfig.ProjectConfig
	createErr error
}

func newFakeRepository() *fakeRepository {
	return &fakeRepository{configs: make(map[string]*projectconfig.ProjectConfig)}
}

func (r *fakeRepository) GetProjectConfigByName(_ context.Context, name string) (*projectconfig.ProjectConfig, error) {
	config, ok := r.configs[name]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	copy := *config
	copy.ConfigValue = append(json.RawMessage(nil), config.ConfigValue...)
	return &copy, nil
}

func (r *fakeRepository) CreateProjectConfig(_ context.Context, config *projectconfig.ProjectConfig) error {
	if r.createErr != nil {
		return r.createErr
	}
	if _, exists := r.configs[config.ConfigName]; exists {
		return errors.New("duplicate")
	}
	copy := *config
	r.configs[config.ConfigName] = &copy
	return nil
}

func TestGetRuleSetToleratesConcurrentInitialMigration(t *testing.T) {
	repo := newFakeRepository()
	legacyJSON := json.RawMessage(`{"blacklist":{"processes":["^xmrig$"]}}`)
	repo.configs[LegacyConfigName] = &projectconfig.ProjectConfig{
		ConfigName: LegacyConfigName, ConfigType: LegacyConfigType, ConfigValue: legacyJSON,
	}
	repo.createErr = errors.New("duplicate key from concurrent replica")
	migrated := ConvertLegacyRules(LegacyRuleSet{Blacklist: LegacyRules{Processes: []string{"^xmrig$"}}})
	migratedJSON, _ := json.Marshal(migrated)

	// Simulate the competing replica winning between our create and the follow-up read.
	originalErr := repo.createErr
	repo.createErr = nil
	repo.configs[V2ConfigName] = &projectconfig.ProjectConfig{
		ConfigName: V2ConfigName, ConfigType: V2ConfigType, ConfigValue: migratedJSON,
	}
	repo.createErr = originalErr

	rules, err := NewService(repo, false).GetRuleSet(context.Background())
	if err != nil {
		t.Fatalf("GetRuleSet() error = %v", err)
	}
	if rules.RulesetRevision != 1 || len(rules.Rules) != 1 {
		t.Fatalf("unexpected migrated rules: %+v", rules)
	}
}

func (r *fakeRepository) UpdateProjectConfig(_ context.Context, config *projectconfig.ProjectConfig) error {
	copy := *config
	r.configs[config.ConfigName] = &copy
	return nil
}

func (r *fakeRepository) ListProjectConfigsByType(
	_ context.Context,
	configType string,
) ([]projectconfig.ProjectConfig, error) {
	configs := make([]projectconfig.ProjectConfig, 0)
	for _, config := range r.configs {
		if config.ConfigType == configType {
			configs = append(configs, *config)
		}
	}
	return configs, nil
}

func (r *fakeRepository) UpdateRuleSetAtomically(
	_ context.Context,
	expectedRevision uint64,
	next RuleSet,
	legacy LegacyRuleSet,
) error {
	current := r.configs[V2ConfigName]
	if current == nil {
		return gorm.ErrRecordNotFound
	}
	var currentRules RuleSet
	if err := json.Unmarshal(current.ConfigValue, &currentRules); err != nil {
		return err
	}
	if currentRules.RulesetRevision != expectedRevision {
		return ErrRevisionConflict
	}
	nextJSON, _ := json.Marshal(next)
	legacyJSON, _ := json.Marshal(legacy)
	current.ConfigValue = nextJSON
	r.configs[LegacyConfigName] = &projectconfig.ProjectConfig{
		ConfigName: LegacyConfigName, ConfigType: LegacyConfigType, ConfigValue: legacyJSON,
	}
	return nil
}

func TestGetRuleSetMigratesLegacyRules(t *testing.T) {
	repo := newFakeRepository()
	repo.configs[LegacyConfigName] = &projectconfig.ProjectConfig{
		ConfigName:  LegacyConfigName,
		ConfigType:  LegacyConfigType,
		ConfigValue: json.RawMessage(`{"blacklist":{"processes":["^xmrig$"]},"whitelist":{"namespaces":["kube-system"]}}`),
	}
	service := NewService(repo, false)

	rules, err := service.GetRuleSet(context.Background())
	if err != nil {
		t.Fatalf("GetRuleSet() error = %v", err)
	}
	if rules.RulesetRevision != 1 || len(rules.Rules) != 1 || rules.Rules[0].Action != ActionAlert {
		t.Fatalf("unexpected migrated rules: %+v", rules)
	}
	if _, ok := repo.configs[V2ConfigName]; !ok {
		t.Fatal("V2 config was not persisted")
	}
}

func TestGetRuleSetRejectsInvalidLegacyRulesBeforePersistingV2(t *testing.T) {
	repo := newFakeRepository()
	repo.configs[LegacyConfigName] = &projectconfig.ProjectConfig{
		ConfigName: LegacyConfigName, ConfigType: LegacyConfigType,
		ConfigValue: json.RawMessage(`{"blacklist":{"processes":["["]}}`),
	}

	_, err := NewService(repo, false).GetRuleSet(context.Background())
	if !errors.Is(err, ErrInvalidRuleSet) {
		t.Fatalf("GetRuleSet() error = %v, want ErrInvalidRuleSet", err)
	}
	if _, exists := repo.configs[V2ConfigName]; exists {
		t.Fatal("invalid legacy rules were persisted as V2")
	}
}

func TestUpdateRuleSetRequiresEnabledWritesAndMatchingRevision(t *testing.T) {
	repo := newFakeRepository()
	service := NewService(repo, false)
	if _, err := service.UpdateRuleSet(context.Background(), 1, RuleSetUpdate{SchemaVersion: SchemaVersion}); !errors.Is(err, ErrV2WritesDisabled) {
		t.Fatalf("UpdateRuleSet() error = %v, want ErrV2WritesDisabled", err)
	}

	service = NewService(repo, true)
	current, err := service.GetRuleSet(context.Background())
	if err != nil {
		t.Fatalf("GetRuleSet() error = %v", err)
	}
	if _, err := service.UpdateRuleSet(context.Background(), current.RulesetRevision+1, RuleSetUpdate{SchemaVersion: SchemaVersion}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("UpdateRuleSet() error = %v, want ErrRevisionConflict", err)
	}
}

func TestUpdateRuleSetIncrementsRevisionAndWritesLegacyProjection(t *testing.T) {
	repo := newFakeRepository()
	service := NewService(repo, true)
	current, err := service.GetRuleSet(context.Background())
	if err != nil {
		t.Fatalf("GetRuleSet() error = %v", err)
	}

	updated, err := service.UpdateRuleSet(context.Background(), current.RulesetRevision, RuleSetUpdate{
		SchemaVersion: SchemaVersion,
		Rules: []Rule{{
			ID: "miner-xmrig", Name: "XMRig", Enabled: true,
			MatchType: MatchTypeProcessName, Pattern: "(?i)^xmrig$",
			Severity: SeverityCritical, Action: ActionBan,
		}},
	})
	if err != nil {
		t.Fatalf("UpdateRuleSet() error = %v", err)
	}
	if updated.RulesetRevision != current.RulesetRevision+1 {
		t.Fatalf("revision = %d, want %d", updated.RulesetRevision, current.RulesetRevision+1)
	}

	legacy, err := service.GetLegacyRuleSet(context.Background())
	if err != nil {
		t.Fatalf("GetLegacyRuleSet() error = %v", err)
	}
	if len(legacy.Blacklist.Processes) != 1 || legacy.Blacklist.Processes[0] != "(?i)^xmrig$" {
		t.Fatalf("unexpected legacy projection: %+v", legacy)
	}
}

func TestGetRuntimeConfigReturnsOnlyProcscanRuntimeFields(t *testing.T) {
	repo := newFakeRepository()
	repo.configs["runtime"] = &projectconfig.ProjectConfig{
		ConfigName: "runtime",
		ConfigType: RuntimeConfigType,
		ConfigValue: json.RawMessage(`{"region":"cn","webhook":"https://example.test/hook"}`),
	}

	runtimeConfig, err := NewService(repo, false).GetRuntimeConfig(context.Background())
	if err != nil {
		t.Fatalf("GetRuntimeConfig() error = %v", err)
	}
	if runtimeConfig.Region != "cn" || runtimeConfig.Webhook != "https://example.test/hook" {
		t.Fatalf("unexpected runtime config: %+v", runtimeConfig)
	}
}

func TestValidateViolationRejectsStaleRevisionAndAcceptsCurrentBanRule(t *testing.T) {
	repo := newFakeRepository()
	service := NewService(repo, true)
	current, err := service.GetRuleSet(context.Background())
	if err != nil {
		t.Fatalf("GetRuleSet() error = %v", err)
	}
	current, err = service.UpdateRuleSet(context.Background(), current.RulesetRevision, RuleSetUpdate{
		SchemaVersion: SchemaVersion,
		Rules: []Rule{{
			ID: "miner-xmrig", Name: "XMRig", Enabled: true,
			MatchType: MatchTypeProcessName, Pattern: "(?i)^xmrig$",
			Severity: SeverityCritical, Action: ActionBan,
		}},
	})
	if err != nil {
		t.Fatalf("UpdateRuleSet() error = %v", err)
	}

	candidate := ViolationCandidate{
		RulesetRevision: current.RulesetRevision - 1,
		PrimaryRuleID: "miner-xmrig", MatchedRuleIDs: []string{"miner-xmrig"},
		MatchType: MatchTypeProcessName, MatchRule: "(?i)^xmrig$",
		Severity: SeverityCritical, RuleAction: ActionBan,
		Sample: ProcessSample{ProcessName: "xmrig", Command: "xmrig --url pool"},
	}
	validation, err := service.ValidateViolation(context.Background(), candidate)
	if err != nil || validation.Reason != "stale_ruleset_revision" {
		t.Fatalf("stale validation = %+v, error = %v", validation, err)
	}

	candidate.RulesetRevision = current.RulesetRevision
	validation, err = service.ValidateViolation(context.Background(), candidate)
	if err != nil || !validation.Eligible || validation.Reason != "eligible" {
		t.Fatalf("current validation = %+v, error = %v", validation, err)
	}
}

func TestCompiledMatcherCachesByRevisionAndInvalidatesAfterUpdate(t *testing.T) {
	repo := newFakeRepository()
	initial := RuleSet{
		SchemaVersion:   SchemaVersion,
		RulesetRevision: 1,
		Rules: []Rule{{
			ID: "miner-xmrig", Name: "XMRig", Enabled: true,
			MatchType: MatchTypeProcessName, Pattern: "(?i)^xmrig$",
			Severity: SeverityCritical, Action: ActionBan,
		}},
	}
	initialJSON, err := json.Marshal(initial)
	if err != nil {
		t.Fatalf("marshal initial rules: %v", err)
	}
	repo.configs[V2ConfigName] = &projectconfig.ProjectConfig{
		ConfigName: V2ConfigName, ConfigType: V2ConfigType, ConfigValue: initialJSON,
	}

	service := NewService(repo, true)
	current, err := service.GetRuleSet(context.Background())
	if err != nil {
		t.Fatalf("GetRuleSet() error = %v", err)
	}
	first, err := service.compiledMatcher(*current)
	if err != nil {
		t.Fatalf("compiledMatcher() error = %v", err)
	}
	second, err := service.compiledMatcher(*current)
	if err != nil {
		t.Fatalf("compiledMatcher() second error = %v", err)
	}
	if first != second {
		t.Fatal("same revision did not reuse the cached matcher")
	}

	updated, err := service.UpdateRuleSet(context.Background(), current.RulesetRevision, RuleSetUpdate{
		SchemaVersion: SchemaVersion,
		Rules: []Rule{{
			ID: "miner-other", Name: "Other", Enabled: true,
			MatchType: MatchTypeProcessName, Pattern: "(?i)^other$",
			Severity: SeverityHigh, Action: ActionBan,
		}},
	})
	if err != nil {
		t.Fatalf("UpdateRuleSet() error = %v", err)
	}
	third, err := service.compiledMatcher(*updated)
	if err != nil {
		t.Fatalf("compiledMatcher() after update error = %v", err)
	}
	if third == first {
		t.Fatal("updated revision reused the stale matcher")
	}
}
