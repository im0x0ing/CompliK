// Copyright 2025 CompliK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package models provides data structures for configuration and process information
// used throughout the process scanner application.
package models

import (
	"time"
)

// --- Configuration structures organized by domain ---

// ScannerConfig contains the core configuration for the scanner itself
type ScannerConfig struct {
	ProcPath             string        `yaml:"proc_path"`
	ScanInterval         time.Duration `yaml:"scan_interval"`
	RulesRefreshInterval time.Duration `yaml:"rules_refresh_interval"`
	HealthPort           int           `yaml:"health_port"`
	LogLevel             string        `yaml:"log_level"`
}

// LarkNotificationConfig contains configuration for Lark notification channel
type LarkNotificationConfig struct {
	Webhook string `yaml:"webhook"`
}

// AdminNotificationConfig contains configuration for the admin API.
type AdminNotificationConfig struct {
	BaseURL   string               `yaml:"base_url"`
	Timeout   time.Duration        `yaml:"timeout"`
	BasicAuth AdminBasicAuthConfig `yaml:"basic_auth"`
}

type AdminBasicAuthConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// NotificationsConfig aggregates all notification channels
type NotificationsConfig struct {
	Lark   LarkNotificationConfig  `yaml:"lark"`
	Admin  AdminNotificationConfig `yaml:"admin"`
	Region string                  `yaml:"region"`
}

// MetricsConfig contains configuration for Prometheus metrics
type MetricsConfig struct {
	Enabled       bool          `yaml:"enabled"`
	Port          int           `yaml:"port"`
	Path          string        `yaml:"path"`
	ReadTimeout   time.Duration `yaml:"read_timeout"`
	WriteTimeout  time.Duration `yaml:"write_timeout"`
	MaxRetries    int           `yaml:"max_retries"`
	RetryInterval time.Duration `yaml:"retry_interval"`
}

// RuleSet defines a set of matching rules, all rules will be parsed as regular expressions
type RuleSet struct {
	Processes  []string `yaml:"processes"`
	Keywords   []string `yaml:"keywords"`
	Commands   []string `yaml:"commands"`
	Namespaces []string `yaml:"namespaces"`
	PodNames   []string `yaml:"podNames"`
}

// DetectionRules contains both blacklist and whitelist rule sets
type DetectionRules struct {
	Blacklist RuleSet `yaml:"blacklist"`
	Whitelist RuleSet `yaml:"whitelist"`
}

type ProcscanRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	MatchType   string `json:"match_type"`
	Pattern     string `json:"pattern"`
	Severity    string `json:"severity"`
	Action      string `json:"action"`
}

type ProcscanExemptions struct {
	Processes  []string `json:"processes"`
	Commands   []string `json:"commands"`
	Namespaces []string `json:"namespaces"`
	PodNames   []string `json:"pod_names"`
}

type ProcscanRuleSet struct {
	SchemaVersion   int                `json:"schema_version"`
	RulesetRevision uint64             `json:"ruleset_revision"`
	Rules           []ProcscanRule     `json:"rules"`
	Exemptions      ProcscanExemptions `json:"exemptions"`
}

// Config is the final, unified top-level configuration structure
type Config struct {
	Scanner        ScannerConfig       `yaml:"scanner"`
	Notifications  NotificationsConfig `yaml:"notifications"`
	Metrics        MetricsConfig       `yaml:"metrics"`
	DetectionRules DetectionRules      `yaml:"detectionRules"`
	ProcscanRules  ProcscanRuleSet     `yaml:"-"`
}

// --- Business data models ---

// ProcessInfo stores complete information for a detected suspicious process.
type ProcessInfo struct {
	PID               int
	ProcessName       string
	Command           string
	PodName           string
	PodUID            string
	Namespace         string
	ContainerID       string
	Timestamp         string
	ProcessStartTime  string
	Message           string
	IsIllegal         bool
	RulesetRevision   uint64
	PrimaryRuleID     string
	MatchedRuleIDs    []string
	MatchType         string
	MatchRule         string
	Severity          string
	RuleAction        string
	AttributionStatus string
	AttributionReason string
}
