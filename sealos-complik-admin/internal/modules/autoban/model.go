package autoban

import "time"

type Source string

const (
	SourceComplik  Source = "complik"
	SourceProcscan Source = "procscan"
)

type Violation struct {
	Namespace     string
	Source        Source
	DetectorName  string
	ProcessName   string
	Summary       string
	Detail        string
	IsIllegal     bool
	IsTest        bool
	DetectedAt    time.Time
	RuleValidated bool
}

type DecisionResult struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

const (
	DecisionNotTriggered = "not_triggered"
	DecisionDryRun       = "dry_run"
	DecisionSubmitted    = "submitted"
	DecisionFailed       = "failed"
)
