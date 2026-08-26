package rules

import (
	"reflect"
	"testing"

	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
)

func TestCompileRejectsCommandKeywordBan(t *testing.T) {
	_, err := Compile(models.ProcscanRuleSet{
		SchemaVersion: 2, RulesetRevision: 1,
		Rules: []models.ProcscanRule{{
			ID: "keyword-ban", Name: "keyword", Enabled: true,
			MatchType: "command_keyword", Pattern: "stratum",
			Severity: "critical", Action: "ban",
		}},
	})
	if err == nil {
		t.Fatal("Compile() error = nil, want invalid command keyword ban")
	}
}

func TestCompileAllowsEmptyRuleSet(t *testing.T) {
	matcher, err := Compile(models.ProcscanRuleSet{
		SchemaVersion:   2,
		RulesetRevision: 9,
	})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if result := matcher.Match(Sample{ProcessName: "xmrig"}); result != nil {
		t.Fatalf("empty matcher matched a process: %+v", result)
	}
}

func TestMatcherUsesDeterministicPriority(t *testing.T) {
	matcher, err := Compile(models.ProcscanRuleSet{
		SchemaVersion: 2, RulesetRevision: 8,
		Rules: []models.ProcscanRule{
			{ID: "z-alert", Name: "alert", Enabled: true, MatchType: "process_name", Pattern: "xmrig", Severity: "critical", Action: "alert"},
			{ID: "z-ban", Name: "ban", Enabled: true, MatchType: "process_name", Pattern: "xmrig", Severity: "high", Action: "ban"},
			{ID: "a-ban", Name: "ban", Enabled: true, MatchType: "process_name", Pattern: "xmrig", Severity: "critical", Action: "ban"},
		},
	})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	result := matcher.Match(Sample{ProcessName: "xmrig", Command: "xmrig --url pool"})
	if result == nil || result.PrimaryRule.ID != "a-ban" {
		t.Fatalf("unexpected primary result: %+v", result)
	}
	want := []string{"a-ban", "z-ban", "z-alert"}
	if !reflect.DeepEqual(result.MatchedRuleIDs, want) {
		t.Fatalf("matched IDs = %v, want %v", result.MatchedRuleIDs, want)
	}
}

func TestMatcherHonorsEveryExemptionClass(t *testing.T) {
	ruleSet := models.ProcscanRuleSet{
		SchemaVersion: 2, RulesetRevision: 1,
		Rules: []models.ProcscanRule{{
			ID: "miner", Name: "miner", Enabled: true, MatchType: "process_name",
			Pattern: "^xmrig$", Severity: "critical", Action: "ban",
		}},
		Exemptions: models.ProcscanExemptions{
			Processes: []string{"^trusted$"}, Commands: []string{"--benchmark"},
			Namespaces: []string{"^kube-system$"}, PodNames: []string{"^monitor-"},
		},
	}
	matcher, err := Compile(ruleSet)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	samples := []Sample{
		{ProcessName: "trusted"},
		{ProcessName: "xmrig", Command: "xmrig --benchmark"},
		{ProcessName: "xmrig", Namespace: "kube-system"},
		{ProcessName: "xmrig", PodName: "monitor-miner"},
	}
	for _, sample := range samples {
		if result := matcher.Match(sample); result != nil {
			t.Fatalf("Match(%+v) = %+v, want exemption", sample, result)
		}
	}
}
