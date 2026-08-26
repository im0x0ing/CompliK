package procscanviolation

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

type ProcscanViolationEvent struct {
	ID                uint64    `gorm:"primaryKey;autoIncrement"                                                                                                                                                                                                     json:"id"`
	EventID           *string   `gorm:"size:64;uniqueIndex"                                                                                                                                                                                                          json:"event_id,omitempty"`
	Namespace         *string   `gorm:"size:255;index:idx_procscan_namespace_time,priority:1"                                                                                                                                                                        json:"namespace"`
	PodName           string    `gorm:"size:255;index:idx_procscan_pod_time,priority:1"                                                                                                                                                                              json:"pod_name,omitempty"`
	PodUID            string    `gorm:"size:128;index"                                                                                                                                                                                                               json:"pod_uid,omitempty"`
	ContainerID       string    `gorm:"size:128;index:idx_procscan_container_time,priority:1"                                                                                                                                                                        json:"container_id,omitempty"`
	NodeName          string    `gorm:"size:128;index:idx_procscan_node_time,priority:1"                                                                                                                                                                             json:"node_name,omitempty"`
	PID               int       `gorm:"not null"                                                                                                                                                                                                                     json:"pid"`
	ProcessName       string    `gorm:"size:255;not null;index:idx_procscan_process_time,priority:1"                                                                                                                                                                 json:"process_name"`
	ProcessCommand    string    `gorm:"type:text;not null"                                                                                                                                                                                                           json:"process_command"`
	MatchType         string    `gorm:"size:32"                                                                                                                                                                                                                      json:"match_type,omitempty"`
	MatchRule         string    `gorm:"size:1024"                                                                                                                                                                                                                    json:"match_rule,omitempty"`
	RulesetRevision   uint64    `gorm:"index"                                                                                                                                                                                                                        json:"ruleset_revision,omitempty"`
	PrimaryRuleID     string    `gorm:"size:255;index"                                                                                                                                                                                                               json:"primary_rule_id,omitempty"`
	MatchedRuleIDs    *string   `gorm:"type:json"                                                                                                                                                                                                                    json:"matched_rule_ids,omitempty"`
	Severity          string    `gorm:"size:16"                                                                                                                                                                                                                      json:"severity,omitempty"`
	RuleAction        string    `gorm:"size:16"                                                                                                                                                                                                                      json:"rule_action,omitempty"`
	AttributionStatus string    `gorm:"size:32;not null;default:unresolved;index"                                                                                                                                                                                     json:"attribution_status"`
	AttributionReason string    `gorm:"size:255"                                                                                                                                                                                                                     json:"attribution_reason,omitempty"`
	AutobanStatus       string     `gorm:"size:32;not null;default:not_triggered;index"                                                                                                                                                                                 json:"autoban_status"`
	AutobanReason       string     `gorm:"size:255"                                                                                                                                                                                                                     json:"autoban_reason,omitempty"`
	AutobanAttemptCount int        `gorm:"not null;default:0"                                                                                                                                                                                                           json:"autoban_attempt_count"`
	AutobanNextRetryAt  *time.Time `gorm:"index"                                                                                                                                                                                                                        json:"autoban_next_retry_at,omitempty"`
	Message           string    `gorm:"type:text;not null"                                                                                                                                                                                                           json:"message"`
	IsIllegal         bool      `gorm:"not null"                                                                                                                                                                                                                     json:"is_illegal"`
	LabelActionStatus string    `gorm:"size:32"                                                                                                                                                                                                                      json:"label_action_status,omitempty"`
	LabelActionResult string    `gorm:"type:text"                                                                                                                                                                                                                    json:"label_action_result,omitempty"`
	DetectedAt        time.Time `gorm:"not null;index:idx_procscan_namespace_time,priority:2;index:idx_procscan_pod_time,priority:2;index:idx_procscan_process_time,priority:2;index:idx_procscan_container_time,priority:2;index:idx_procscan_node_time,priority:2" json:"detected_at"`
	RawPayload        *string   `gorm:"type:json"                                                                                                                                                                                                                    json:"raw_payload,omitempty"`
	CreatedAt         time.Time `gorm:"autoCreateTime"                                                                                                                                                                                                               json:"created_at"`
	UpdatedAt         time.Time `gorm:"autoUpdateTime"                                                                                                                                                                                                               json:"updated_at"`
}

func (ProcscanViolationEvent) TableName() string {
	return "procscan_violation_events"
}

func AutoMigrate(db *gorm.DB) error {
	if db == nil {
		return errors.New("procscan violation automigrate: database is nil")
	}

	if db.Migrator().HasColumn(&ProcscanViolationEvent{}, "EventID") {
		if err := db.Exec(
			"UPDATE procscan_violation_events SET event_id = NULL WHERE event_id = ''",
		).Error; err != nil {
			return fmt.Errorf("procscan violation normalize empty event ids: %w", err)
		}
	}
	if err := db.AutoMigrate(&ProcscanViolationEvent{}); err != nil {
		return fmt.Errorf("procscan violation automigrate: %w", err)
	}
	if err := db.Migrator().AlterColumn(&ProcscanViolationEvent{}, "Namespace"); err != nil {
		return fmt.Errorf("procscan violation make namespace nullable: %w", err)
	}

	return nil
}
