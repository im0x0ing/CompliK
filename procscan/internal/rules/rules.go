package rules

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
)

const maxPatternLength = 1024

type Sample struct {
	ProcessName string
	Command     string
	Namespace   string
	PodName     string
}

type MatchResult struct {
	PrimaryRule    models.ProcscanRule
	MatchedRuleIDs []string
}

type compiledRule struct {
	rule models.ProcscanRule
	re   *regexp.Regexp
}

type Matcher struct {
	rules            []compiledRule
	exemptProcesses  []*regexp.Regexp
	exemptCommands   []*regexp.Regexp
	exemptNamespaces []*regexp.Regexp
	exemptPodNames   []*regexp.Regexp
}

func Compile(ruleSet models.ProcscanRuleSet) (*Matcher, error) {
	if ruleSet.SchemaVersion != 2 || ruleSet.RulesetRevision == 0 {
		return nil, errors.New("ruleset requires schema version 2 and a positive revision")
	}
	matcher := &Matcher{rules: make([]compiledRule, 0, len(ruleSet.Rules))}
	seenIDs := make(map[string]struct{}, len(ruleSet.Rules))
	for i, rule := range ruleSet.Rules {
		compiled, err := compileRule(rule)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		if _, exists := seenIDs[rule.ID]; exists {
			return nil, fmt.Errorf("rule %d: duplicate id %q", i, rule.ID)
		}
		seenIDs[rule.ID] = struct{}{}
		matcher.rules = append(matcher.rules, compiled)
	}

	var err error
	if matcher.exemptProcesses, err = compilePatterns(ruleSet.Exemptions.Processes); err != nil {
		return nil, fmt.Errorf("process exemptions: %w", err)
	}
	if matcher.exemptCommands, err = compilePatterns(ruleSet.Exemptions.Commands); err != nil {
		return nil, fmt.Errorf("command exemptions: %w", err)
	}
	if matcher.exemptNamespaces, err = compilePatterns(ruleSet.Exemptions.Namespaces); err != nil {
		return nil, fmt.Errorf("namespace exemptions: %w", err)
	}
	if matcher.exemptPodNames, err = compilePatterns(ruleSet.Exemptions.PodNames); err != nil {
		return nil, fmt.Errorf("pod exemptions: %w", err)
	}
	return matcher, nil
}

func compileRule(rule models.ProcscanRule) (compiledRule, error) {
	if strings.TrimSpace(rule.ID) == "" || strings.TrimSpace(rule.Name) == "" {
		return compiledRule{}, errors.New("id and name are required")
	}
	if len(rule.Pattern) == 0 || len(rule.Pattern) > maxPatternLength {
		return compiledRule{}, fmt.Errorf("pattern length must be between 1 and %d bytes", maxPatternLength)
	}
	if rule.MatchType != "process_name" && rule.MatchType != "command_keyword" {
		return compiledRule{}, fmt.Errorf("invalid match type %q", rule.MatchType)
	}
	if rule.Severity != "low" && rule.Severity != "medium" && rule.Severity != "high" && rule.Severity != "critical" {
		return compiledRule{}, fmt.Errorf("invalid severity %q", rule.Severity)
	}
	if rule.Action != "alert" && rule.Action != "ban" {
		return compiledRule{}, fmt.Errorf("invalid action %q", rule.Action)
	}
	if rule.Action == "ban" && (rule.MatchType != "process_name" || (rule.Severity != "high" && rule.Severity != "critical")) {
		return compiledRule{}, errors.New("ban requires a high or critical process_name rule")
	}
	re, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return compiledRule{}, fmt.Errorf("invalid pattern: %w", err)
	}
	return compiledRule{rule: rule, re: re}, nil
}

func compilePatterns(patterns []string) ([]*regexp.Regexp, error) {
	result := make([]*regexp.Regexp, 0, len(patterns))
	for i, pattern := range patterns {
		if len(pattern) == 0 || len(pattern) > maxPatternLength {
			return nil, fmt.Errorf("pattern %d has invalid length", i)
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("pattern %d: %w", i, err)
		}
		result = append(result, re)
	}
	return result, nil
}

func (m *Matcher) Match(sample Sample) *MatchResult {
	if m == nil || matchesAny(sample.ProcessName, m.exemptProcesses) ||
		matchesAny(sample.Command, m.exemptCommands) ||
		matchesAny(sample.Namespace, m.exemptNamespaces) ||
		matchesAny(sample.PodName, m.exemptPodNames) {
		return nil
	}

	matched := make([]models.ProcscanRule, 0)
	for _, compiled := range m.rules {
		if !compiled.rule.Enabled {
			continue
		}
		value := sample.ProcessName
		if compiled.rule.MatchType == "command_keyword" {
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

func actionRank(action string) int {
	if action == "ban" {
		return 2
	}
	return 1
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
