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

package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/bearslyricattack/CompliK/procscan/internal/adminauth"
	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
	"gopkg.in/yaml.v3"
)

const (
	procscanRuntimeConfigPath = "/api/procscan/runtime-config"
	procscanRulesPath         = "/api/procscan/rules"
	procscanLegacyRulesPath   = "/api/procscan/rules/legacy"
	defaultAdminConfigTimeout = 5 * time.Second
)

var defaultAdminClient = &http.Client{Timeout: defaultAdminConfigTimeout}

// Loader handles configuration file loading and parsing
type Loader struct {
	configPath string
	lastHash   string
	rulesETag  string
	lastRules  models.ProcscanRuleSet
	mu         sync.Mutex
}

type remoteNotificationsConfig struct {
	Region  *string `json:"region"`
	Webhook *string `json:"webhook"`
}

// NewLoader creates a new configuration loader
func NewLoader(configPath string) *Loader {
	return &Loader{
		configPath: configPath,
	}
}

// Load reads and parses the configuration file
func (l *Loader) Load() (*models.Config, error) {
	config, err := l.LoadLocal()
	if err != nil {
		return nil, err
	}
	if err := l.LoadRemote(context.Background(), config); err != nil {
		return nil, err
	}
	return config, nil
}

func (l *Loader) LoadLocal() (*models.Config, error) {
	if _, err := os.Stat(l.configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration file does not exist: %s", l.configPath)
	}

	data, err := os.ReadFile(l.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("configuration file is empty: %s", l.configPath)
	}

	var config models.Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse configuration file: %w", err)
	}
	if config.Scanner.ProcPath == "" {
		config.Scanner.ProcPath = "/host/proc"
	}
	if config.Scanner.ScanInterval <= 0 {
		config.Scanner.ScanInterval = 100 * time.Second
	}
	if config.Scanner.RulesRefreshInterval <= 0 {
		config.Scanner.RulesRefreshInterval = 30 * time.Second
	}
	if config.Scanner.HealthPort <= 0 {
		config.Scanner.HealthPort = 8081
	}
	if config.Scanner.LogLevel == "" {
		config.Scanner.LogLevel = "info"
	}

	// Update last hash after the file has been parsed successfully.
	hash, hashErr := l.calculateHash()
	if hashErr != nil {
		return nil, fmt.Errorf("hash configuration file: %w", hashErr)
	}
	l.mu.Lock()
	l.lastHash = hash
	l.mu.Unlock()

	return &config, nil
}

func (l *Loader) Refresh(ctx context.Context, previous *models.Config) (*models.Config, error) {
	config, err := l.LoadLocal()
	if err != nil {
		return nil, err
	}
	if previous != nil {
		config.ProcscanRules = previous.ProcscanRules
	}
	if err := l.LoadRemote(ctx, config); err != nil {
		return nil, err
	}
	return config, nil
}

func (l *Loader) LoadRemote(ctx context.Context, config *models.Config) error {
	if config == nil {
		return errors.New("config is required")
	}
	adminBaseURL := strings.TrimSpace(config.Notifications.Admin.BaseURL)
	if adminBaseURL == "" {
		return errors.New("notifications.admin.base_url is required")
	}

	auth := adminauth.FromValues(
		config.Notifications.Admin.BasicAuth.Username,
		config.Notifications.Admin.BasicAuth.Password,
	)

	notifications, _, _, err := loadRemoteJSON[remoteNotificationsConfig](
		ctx,
		adminBaseURL,
		procscanRuntimeConfigPath,
		config.Notifications.Admin.Timeout,
		auth,
		"",
	)
	if err != nil {
		return fmt.Errorf("load notifications config from admin: %w", err)
	}

	if notifications.Region == nil || strings.TrimSpace(*notifications.Region) == "" {
		return errors.New("procscan runtime config missing region")
	}

	if notifications.Webhook == nil || strings.TrimSpace(*notifications.Webhook) == "" {
		return errors.New("procscan runtime config missing webhook")
	}

	config.Notifications.Region = strings.TrimSpace(*notifications.Region)
	config.Notifications.Lark.Webhook = strings.TrimSpace(*notifications.Webhook)

	rules, err := l.loadRemoteRules(
		ctx,
		adminBaseURL,
		config.Notifications.Admin.Timeout,
		auth,
		config.ProcscanRules,
	)
	if err != nil {
		return fmt.Errorf("load detection rules config from admin: %w", err)
	}
	config.ProcscanRules = rules

	return nil
}

func (l *Loader) loadRemoteRules(
	ctx context.Context,
	adminBaseURL string,
	timeout time.Duration,
	auth adminauth.BasicAuth,
	current models.ProcscanRuleSet,
) (models.ProcscanRuleSet, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	rules, etag, status, err := loadRemoteJSON[models.ProcscanRuleSet](
		ctx,
		adminBaseURL,
		procscanRulesPath,
		timeout,
		auth,
		l.rulesETag,
	)
	if err == nil {
		if status == http.StatusNotModified {
			if l.lastRules.RulesetRevision > current.RulesetRevision {
				return l.lastRules, nil
			}
			if current.RulesetRevision > 0 {
				return current, nil
			}
			return models.ProcscanRuleSet{}, errors.New("rules returned not modified without a cached ruleset")
		}
		if rules.RulesetRevision < l.lastRules.RulesetRevision {
			return models.ProcscanRuleSet{}, fmt.Errorf(
				"ruleset revision regressed from %d to %d",
				l.lastRules.RulesetRevision,
				rules.RulesetRevision,
			)
		}
		l.rulesETag = etag
		l.lastRules = *rules
		return *rules, nil
	}
	if status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
		return models.ProcscanRuleSet{}, err
	}

	legacy, _, _, legacyErr := loadRemoteJSON[models.DetectionRules](
		ctx,
		adminBaseURL,
		procscanLegacyRulesPath,
		timeout,
		auth,
		"",
	)
	if legacyErr != nil {
		return models.ProcscanRuleSet{}, errors.Join(err, legacyErr)
	}
	converted := convertLegacyRules(*legacy)
	if converted.RulesetRevision < l.lastRules.RulesetRevision {
		return models.ProcscanRuleSet{}, fmt.Errorf(
			"legacy ruleset revision %d would regress current revision %d",
			converted.RulesetRevision,
			l.lastRules.RulesetRevision,
		)
	}
	l.rulesETag = ""
	l.lastRules = converted
	return converted, nil
}

func loadRemoteJSON[T any](
	parent context.Context,
	adminBaseURL string,
	path string,
	timeout time.Duration,
	auth adminauth.BasicAuth,
	etag string,
) (*T, string, int, error) {
	if timeout <= 0 {
		timeout = defaultAdminConfigTimeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	endpoint := strings.TrimRight(adminBaseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, "", 0, fmt.Errorf("create request: %w", err)
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	auth.Apply(req)

	resp, err := adminClient(timeout).Do(req)
	if err != nil {
		return nil, "", 0, fmt.Errorf("request %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, resp.Header.Get("ETag"), resp.StatusCode, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, "", resp.StatusCode, fmt.Errorf(
			"request %s: status %d, body %s",
			path,
			resp.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	var payload T
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, "", resp.StatusCode, fmt.Errorf("decode %s response: %w", path, err)
	}
	return &payload, resp.Header.Get("ETag"), resp.StatusCode, nil
}

func convertLegacyRules(legacy models.DetectionRules) models.ProcscanRuleSet {
	rules := make([]models.ProcscanRule, 0, len(legacy.Blacklist.Processes)+len(legacy.Blacklist.Keywords))
	appendRules := func(matchType, prefix string, patterns []string) {
		for _, pattern := range patterns {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			sum := sha256.Sum256([]byte(matchType + "\x00" + pattern))
			rules = append(rules, models.ProcscanRule{
				ID: prefix + "-" + hex.EncodeToString(sum[:])[:16], Name: "Legacy rule: " + pattern,
				Enabled: true, MatchType: matchType, Pattern: pattern, Severity: "medium", Action: "alert",
			})
		}
	}
	appendRules("process_name", "legacy-process", legacy.Blacklist.Processes)
	appendRules("command_keyword", "legacy-keyword", legacy.Blacklist.Keywords)
	return models.ProcscanRuleSet{
		SchemaVersion: 2, RulesetRevision: 1, Rules: rules,
		Exemptions: models.ProcscanExemptions{
			Processes: legacy.Whitelist.Processes, Commands: legacy.Whitelist.Commands,
			Namespaces: legacy.Whitelist.Namespaces, PodNames: legacy.Whitelist.PodNames,
		},
	}
}

func adminClient(timeout time.Duration) *http.Client {
	if timeout <= 0 || timeout == defaultAdminConfigTimeout {
		return defaultAdminClient
	}
	return &http.Client{Timeout: timeout}
}

// HasChanged checks if the configuration file has changed since last load
func (l *Loader) HasChanged() (bool, error) {
	currentHash, err := l.calculateHash()
	if err != nil {
		return false, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.lastHash == "" {
		l.lastHash = currentHash
		return false, nil
	}

	changed := currentHash != l.lastHash
	if changed {
		l.lastHash = currentHash
	}

	return changed, nil
}

// GetConfigPath returns the configuration file path
func (l *Loader) GetConfigPath() string {
	return l.configPath
}

// GetConfigDir returns the directory containing the configuration file
func (l *Loader) GetConfigDir() string {
	return filepath.Dir(l.configPath)
}

// calculateHash computes SHA256 hash of the configuration file
func (l *Loader) calculateHash() (string, error) {
	file, err := os.Open(l.configPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}
