package scanner

import (
	"testing"

	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
)

func TestApplyConfigRejectsRulesetRevisionRollback(t *testing.T) {
	current := scannerTestConfig(8)
	s := NewScanner(current)

	if err := s.ApplyConfig(scannerTestConfig(7)); err == nil {
		t.Fatal("ApplyConfig() error = nil, want revision rollback rejection")
	}
	if got := s.CurrentConfig().ProcscanRules.RulesetRevision; got != 8 {
		t.Fatalf("current revision = %d, want 8", got)
	}
}

func scannerTestConfig(revision uint64) *models.Config {
	return &models.Config{
		ProcscanRules: models.ProcscanRuleSet{
			SchemaVersion: 2, RulesetRevision: revision,
			Rules: []models.ProcscanRule{{
				ID: "miner", Name: "miner", Enabled: true,
				MatchType: "process_name", Pattern: "^xmrig$",
				Severity: "critical", Action: "ban",
			}},
		},
	}
}
