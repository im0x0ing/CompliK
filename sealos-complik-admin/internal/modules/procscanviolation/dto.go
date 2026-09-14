package procscanviolation

import (
	"encoding/json"
	"time"

	"sealos-complik-admin/internal/modules/pagequery"
)

type NamespaceRequest struct {
	Namespace string `uri:"namespace" binding:"required,max=255"`
}

type ViolationIDRequest struct {
	ID uint64 `uri:"id" binding:"required,min=1"`
}

type CreateViolationRequest struct {
	EventID           string          `json:"event_id"            binding:"omitempty,max=64"`
	Namespace         *string         `json:"namespace"           binding:"omitempty,max=255"`
	PodName           string          `json:"pod_name"            binding:"omitempty,max=255"`
	PodUID            string          `json:"pod_uid"              binding:"omitempty,max=128"`
	ContainerID       string          `json:"container_id"        binding:"omitempty,max=128"`
	NodeName          string          `json:"node_name"           binding:"omitempty,max=128"`
	PID               int             `json:"pid"                 binding:"required,min=1"`
	ProcessName       string          `json:"process_name"        binding:"required,max=255"`
	ProcessCommand    string          `json:"process_command"     binding:"required,max=4096"`
	MatchType         string          `json:"match_type"          binding:"omitempty,max=32"`
	MatchRule         string          `json:"match_rule"          binding:"omitempty,max=1024"`
	RulesetRevision   uint64          `json:"ruleset_revision"`
	PrimaryRuleID     string          `json:"primary_rule_id"     binding:"omitempty,max=255"`
	MatchedRuleIDs    []string        `json:"matched_rule_ids"`
	Severity          string          `json:"severity"            binding:"omitempty,max=16"`
	RuleAction        string          `json:"rule_action"         binding:"omitempty,max=16"`
	AttributionStatus string          `json:"attribution_status"  binding:"omitempty,max=32"`
	AttributionReason string          `json:"attribution_reason"  binding:"omitempty,max=255"`
	Message           string          `json:"message"             binding:"required,max=4096"`
	IsIllegal         *bool           `json:"is_illegal"`
	LabelActionStatus string          `json:"label_action_status" binding:"omitempty,max=32"`
	LabelActionResult string          `json:"label_action_result" binding:"omitempty,max=4096"`
	DetectedAt        time.Time       `json:"detected_at"         binding:"required"`
	RawPayload        json.RawMessage `json:"raw_payload"         binding:"omitempty,max=65536"`
}

type ViolationResponse struct {
	ID                uint64          `json:"id"`
	EventID           string          `json:"event_id"`
	Namespace         *string         `json:"namespace"`
	PodName           string          `json:"pod_name,omitempty"`
	PodUID            string          `json:"pod_uid,omitempty"`
	ContainerID       string          `json:"container_id,omitempty"`
	NodeName          string          `json:"node_name,omitempty"`
	PID               int             `json:"pid"`
	ProcessName       string          `json:"process_name"`
	ProcessCommand    string          `json:"process_command"`
	MatchType         string          `json:"match_type,omitempty"`
	MatchRule         string          `json:"match_rule,omitempty"`
	RulesetRevision   uint64          `json:"ruleset_revision,omitempty"`
	PrimaryRuleID     string          `json:"primary_rule_id,omitempty"`
	MatchedRuleIDs    []string        `json:"matched_rule_ids,omitempty"`
	Severity          string          `json:"severity,omitempty"`
	RuleAction        string          `json:"rule_action,omitempty"`
	AttributionStatus string          `json:"attribution_status"`
	AttributionReason string          `json:"attribution_reason,omitempty"`
	AutobanStatus     string          `json:"autoban_status"`
	AutobanReason     string          `json:"autoban_reason,omitempty"`
	Message           string          `json:"message"`
	IsIllegal         bool            `json:"is_illegal"`
	LabelActionStatus string          `json:"label_action_status,omitempty"`
	LabelActionResult string          `json:"label_action_result,omitempty"`
	DetectedAt        time.Time       `json:"detected_at"`
	RawPayload        json.RawMessage `json:"raw_payload,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

type ViolationStatusResponse struct {
	Violated bool `json:"violated"`
}

type PaginatedViolationResponse = pagequery.PaginatedResponse[ViolationResponse]
