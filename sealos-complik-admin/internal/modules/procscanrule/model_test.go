package procscanrule

import (
	"reflect"
	"testing"
)

func TestConvertLegacyRulesProducesStableAlertRules(t *testing.T) {
	legacy := LegacyRuleSet{
		Blacklist: LegacyRules{
			Processes: []string{"(?i)^xmrig$"},
			Keywords:  []string{"stratum\\+tcp"},
		},
		Whitelist: LegacyRules{
			Processes:  []string{"^trusted-miner$"},
			Commands:   []string{"--benchmark"},
			Namespaces: []string{"kube-system"},
			PodNames:   []string{"^monitor-"},
		},
	}

	first := ConvertLegacyRules(legacy)
	second := ConvertLegacyRules(legacy)

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("legacy conversion is not stable:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if first.SchemaVersion != SchemaVersion || first.RulesetRevision != 1 {
		t.Fatalf("unexpected version: %+v", first)
	}
	if len(first.Rules) != 2 {
		t.Fatalf("rules length = %d, want 2", len(first.Rules))
	}
	for _, rule := range first.Rules {
		if rule.Action != ActionAlert || rule.Severity != SeverityMedium {
			t.Fatalf("legacy rule gained enforcement eligibility: %+v", rule)
		}
	}
	if got := first.Exemptions.Namespaces; !reflect.DeepEqual(got, []string{"kube-system"}) {
		t.Fatalf("namespace exemptions = %v", got)
	}
}

func TestValidateRejectsCommandKeywordBan(t *testing.T) {
	rules := RuleSet{
		SchemaVersion:   SchemaVersion,
		RulesetRevision: 1,
		Rules: []Rule{{
			ID:        "keyword-ban",
			Name:      "Keyword ban",
			Enabled:   true,
			MatchType: MatchTypeCommandKeyword,
			Pattern:   "stratum",
			Severity:  SeverityCritical,
			Action:    ActionBan,
		}},
	}

	if err := ValidateRuleSet(rules); err == nil {
		t.Fatal("ValidateRuleSet() error = nil, want command keyword ban rejection")
	}
}

func TestCompileAllowsEmptyRuleSet(t *testing.T) {
	matcher, err := CompileRuleSet(RuleSet{
		SchemaVersion:   SchemaVersion,
		RulesetRevision: 9,
	})
	if err != nil {
		t.Fatalf("CompileRuleSet() error = %v", err)
	}
	if result := matcher.Match(ProcessSample{ProcessName: "xmrig"}); result != nil {
		t.Fatalf("empty matcher matched a process: %+v", result)
	}
}
