package procscanrule

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

const (
	SchemaVersion    = 2
	maxPatternLength = 1024
)

type MatchType string

const (
	MatchTypeProcessName    MatchType = "process_name"
	MatchTypeCommandKeyword MatchType = "command_keyword"
)

type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type Action string

const (
	ActionAlert Action = "alert"
	ActionBan   Action = "ban"
)

type Rule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Enabled     bool      `json:"enabled"`
	MatchType   MatchType `json:"match_type"`
	Pattern     string    `json:"pattern"`
	Severity    Severity  `json:"severity"`
	Action      Action    `json:"action"`
}

type Exemptions struct {
	Processes  []string `json:"processes"`
	Commands   []string `json:"commands"`
	Namespaces []string `json:"namespaces"`
	PodNames   []string `json:"pod_names"`
}

type RuleSet struct {
	SchemaVersion   int        `json:"schema_version"`
	RulesetRevision uint64     `json:"ruleset_revision"`
	Rules           []Rule     `json:"rules"`
	Exemptions      Exemptions `json:"exemptions"`
}

type LegacyRules struct {
	Processes  []string `json:"processes"`
	Keywords   []string `json:"keywords"`
	Commands   []string `json:"commands"`
	Namespaces []string `json:"namespaces"`
	PodNames   []string `json:"podNames"`
}

type LegacyRuleSet struct {
	Blacklist LegacyRules `json:"blacklist"`
	Whitelist LegacyRules `json:"whitelist"`
}

type ProcessSample struct {
	ProcessName string
	Command     string
	Namespace   string
	PodName     string
}

type MatchResult struct {
	PrimaryRule   Rule
	MatchedRuleIDs []string
}

type ViolationCandidate struct {
	RulesetRevision uint64
	PrimaryRuleID   string
	MatchedRuleIDs  []string
	MatchType       MatchType
	MatchRule       string
	Severity        Severity
	RuleAction      Action
	Sample          ProcessSample
}

type ViolationValidation struct {
	Eligible bool
	Reason   string
	Match    *MatchResult
}

type compiledRule struct {
	rule Rule
	re   *regexp.Regexp
}

type Matcher struct {
	rules               []compiledRule
	exemptProcesses     []*regexp.Regexp
	exemptCommands      []*regexp.Regexp
	exemptNamespaces    []*regexp.Regexp
	exemptPodNames      []*regexp.Regexp
}

func ValidateRuleSet(rules RuleSet) error {
	if rules.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	if rules.RulesetRevision == 0 {
		return errors.New("ruleset_revision must be greater than zero")
	}

	seenIDs := make(map[string]struct{}, len(rules.Rules))
	for i := range rules.Rules {
		rule := rules.Rules[i]
		if err := validateRule(rule); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
		if _, exists := seenIDs[rule.ID]; exists {
			return fmt.Errorf("rule %d: duplicate id %q", i, rule.ID)
		}
		seenIDs[rule.ID] = struct{}{}
	}

	for name, patterns := range map[string][]string{
		"exemptions.processes":  rules.Exemptions.Processes,
		"exemptions.commands":   rules.Exemptions.Commands,
		"exemptions.namespaces": rules.Exemptions.Namespaces,
		"exemptions.pod_names":  rules.Exemptions.PodNames,
	} {
		if _, err := compilePatterns(patterns); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}

	return nil
}

func validateRule(rule Rule) error {
	if strings.TrimSpace(rule.ID) == "" {
		return errors.New("id is required")
	}
	if strings.TrimSpace(rule.Name) == "" {
		return errors.New("name is required")
	}
	if strings.TrimSpace(rule.Pattern) == "" {
		return errors.New("pattern is required")
	}
	if len(rule.Pattern) > maxPatternLength {
		return fmt.Errorf("pattern exceeds %d bytes", maxPatternLength)
	}
	if !slices.Contains([]MatchType{MatchTypeProcessName, MatchTypeCommandKeyword}, rule.MatchType) {
		return fmt.Errorf("invalid match_type %q", rule.MatchType)
	}
	if !slices.Contains([]Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}, rule.Severity) {
		return fmt.Errorf("invalid severity %q", rule.Severity)
	}
	if !slices.Contains([]Action{ActionAlert, ActionBan}, rule.Action) {
		return fmt.Errorf("invalid action %q", rule.Action)
	}
	if rule.Action == ActionBan && (rule.MatchType != MatchTypeProcessName ||
		(rule.Severity != SeverityHigh && rule.Severity != SeverityCritical)) {
		return errors.New("ban requires a high or critical process_name rule")
	}
	if _, err := regexp.Compile(rule.Pattern); err != nil {
		return fmt.Errorf("invalid pattern: %w", err)
	}
	return nil
}

func CompileRuleSet(rules RuleSet) (*Matcher, error) {
	if err := ValidateRuleSet(rules); err != nil {
		return nil, err
	}

	matcher := &Matcher{rules: make([]compiledRule, 0, len(rules.Rules))}
	for _, rule := range rules.Rules {
		matcher.rules = append(matcher.rules, compiledRule{rule: rule, re: regexp.MustCompile(rule.Pattern)})
	}

	var err error
	if matcher.exemptProcesses, err = compilePatterns(rules.Exemptions.Processes); err != nil {
		return nil, err
	}
	if matcher.exemptCommands, err = compilePatterns(rules.Exemptions.Commands); err != nil {
		return nil, err
	}
	if matcher.exemptNamespaces, err = compilePatterns(rules.Exemptions.Namespaces); err != nil {
		return nil, err
	}
	if matcher.exemptPodNames, err = compilePatterns(rules.Exemptions.PodNames); err != nil {
		return nil, err
	}

	return matcher, nil
}

func (m *Matcher) Match(sample ProcessSample) *MatchResult {
	if m == nil || matchesAny(sample.ProcessName, m.exemptProcesses) ||
		matchesAny(sample.Command, m.exemptCommands) ||
		matchesAny(sample.Namespace, m.exemptNamespaces) ||
		matchesAny(sample.PodName, m.exemptPodNames) {
		return nil
	}

	matched := make([]Rule, 0)
	for _, compiled := range m.rules {
		if !compiled.rule.Enabled {
			continue
		}
		value := sample.ProcessName
		if compiled.rule.MatchType == MatchTypeCommandKeyword {
			value = sample.Command
		}
		if compiled.re.MatchString(value) {
			matched = append(matched, compiled.rule)
		}
	}
	if len(matched) == 0 {
		return nil
	}

	sort.Slice(matched, func(i, j int) bool {
		if actionRank(matched[i].Action) != actionRank(matched[j].Action) {
			return actionRank(matched[i].Action) > actionRank(matched[j].Action)
		}
		if severityRank(matched[i].Severity) != severityRank(matched[j].Severity) {
			return severityRank(matched[i].Severity) > severityRank(matched[j].Severity)
		}
		return matched[i].ID < matched[j].ID
	})

	ids := make([]string, 0, len(matched))
	for _, rule := range matched {
		ids = append(ids, rule.ID)
	}
	return &MatchResult{PrimaryRule: matched[0], MatchedRuleIDs: ids}
}

func ConvertLegacyRules(legacy LegacyRuleSet) RuleSet {
	rules := make([]Rule, 0, len(legacy.Blacklist.Processes)+len(legacy.Blacklist.Keywords))
	seen := make(map[string]struct{})
	appendLegacy := func(matchType MatchType, prefix string, patterns []string) {
		for _, pattern := range patterns {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			key := string(matchType) + "\x00" + pattern
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			rules = append(rules, Rule{
				ID:        prefix + "-" + stablePatternHash(key),
				Name:      "Legacy rule: " + pattern,
				Enabled:   true,
				MatchType: matchType,
				Pattern:   pattern,
				Severity:  SeverityMedium,
				Action:    ActionAlert,
			})
		}
	}
	appendLegacy(MatchTypeProcessName, "legacy-process", legacy.Blacklist.Processes)
	appendLegacy(MatchTypeCommandKeyword, "legacy-keyword", legacy.Blacklist.Keywords)

	return RuleSet{
		SchemaVersion:   SchemaVersion,
		RulesetRevision: 1,
		Rules:           rules,
		Exemptions: Exemptions{
			Processes:  trimUnique(legacy.Whitelist.Processes),
			Commands:   trimUnique(legacy.Whitelist.Commands),
			Namespaces: trimUnique(legacy.Whitelist.Namespaces),
			PodNames:   trimUnique(legacy.Whitelist.PodNames),
		},
	}
}

func LegacyProjection(rules RuleSet) LegacyRuleSet {
	legacy := LegacyRuleSet{Whitelist: LegacyRules{
		Processes:  append([]string(nil), rules.Exemptions.Processes...),
		Commands:   append([]string(nil), rules.Exemptions.Commands...),
		Namespaces: append([]string(nil), rules.Exemptions.Namespaces...),
		PodNames:   append([]string(nil), rules.Exemptions.PodNames...),
	}}
	for _, rule := range rules.Rules {
		if !rule.Enabled {
			continue
		}
		if rule.MatchType == MatchTypeProcessName {
			legacy.Blacklist.Processes = append(legacy.Blacklist.Processes, rule.Pattern)
		} else {
			legacy.Blacklist.Keywords = append(legacy.Blacklist.Keywords, rule.Pattern)
		}
	}
	legacy.Blacklist.Processes = trimUnique(legacy.Blacklist.Processes)
	legacy.Blacklist.Keywords = trimUnique(legacy.Blacklist.Keywords)
	return legacy
}

func compilePatterns(patterns []string) ([]*regexp.Regexp, error) {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for i, pattern := range patterns {
		if strings.TrimSpace(pattern) == "" {
			return nil, fmt.Errorf("pattern %d is empty", i)
		}
		if len(pattern) > maxPatternLength {
			return nil, fmt.Errorf("pattern %d exceeds %d bytes", i, maxPatternLength)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("pattern %d is invalid: %w", i, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

func matchesAny(value string, patterns []*regexp.Regexp) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	for _, pattern := range patterns {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}

func trimUnique(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func stablePatternHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:16]
}

func actionRank(action Action) int {
	if action == ActionBan {
		return 2
	}
	return 1
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
