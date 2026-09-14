package procscanviolation

import (
	"context"
	"testing"
)

func TestUpdateAutobanDecisionIfAttemptRequiresTx(t *testing.T) {
	t.Parallel()

	repo := &Repository{}
	updated, err := repo.UpdateAutobanDecisionIfAttempt(
		context.Background(),
		nil,
		1,
		"failed",
		"ban_submission_failed",
		1,
		nil,
		0,
	)
	if updated {
		t.Fatal("UpdateAutobanDecisionIfAttempt() updated=true without a transaction")
	}
	if err == nil {
		t.Fatal("UpdateAutobanDecisionIfAttempt() err=nil, want missing transaction")
	}
}
