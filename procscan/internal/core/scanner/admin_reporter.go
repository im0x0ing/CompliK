package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bearslyricattack/CompliK/procscan/internal/adminauth"
	legacy "github.com/bearslyricattack/CompliK/procscan/pkg/logger/legacy"
	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
)

const (
	defaultAdminTimeout = 10 * time.Second
	adminViolationsPath = "/api/procscan-violations"
)

type procscanViolationRequest struct {
	EventID           string    `json:"event_id"`
	Namespace         *string   `json:"namespace"`
	PodName           string    `json:"pod_name,omitempty"`
	PodUID            string    `json:"pod_uid,omitempty"`
	ContainerID       string    `json:"container_id,omitempty"`
	NodeName          string    `json:"node_name,omitempty"`
	PID               int       `json:"pid"`
	ProcessName       string    `json:"process_name"`
	ProcessCommand    string    `json:"process_command"`
	MatchType         string    `json:"match_type,omitempty"`
	MatchRule         string    `json:"match_rule,omitempty"`
	RulesetRevision   uint64    `json:"ruleset_revision,omitempty"`
	PrimaryRuleID     string    `json:"primary_rule_id,omitempty"`
	MatchedRuleIDs    []string  `json:"matched_rule_ids,omitempty"`
	Severity          string    `json:"severity,omitempty"`
	RuleAction        string    `json:"rule_action,omitempty"`
	AttributionStatus string    `json:"attribution_status"`
	AttributionReason string    `json:"attribution_reason,omitempty"`
	Message           string    `json:"message"`
	IsIllegal         bool      `json:"is_illegal"`
	DetectedAt        time.Time `json:"detected_at"`
	RawPayload        any       `json:"raw_payload,omitempty"`
}

func (s *Scanner) reportProcscanViolations(processInfos []*models.ProcessInfo) {
	endpoint, ok := s.adminEndpoint()
	if !ok {
		legacy.L.Info("Admin reporting is disabled because notifications.admin.base_url is empty")
		return
	}

	for _, processInfo := range processInfos {
		if processInfo == nil {
			continue
		}

		if err := s.reportProcscanViolation(endpoint, processInfo); err != nil {
			legacy.L.WithFields(map[string]any{
				"namespace": processInfo.Namespace,
				"pod":       processInfo.PodName,
				"pid":       processInfo.PID,
				"error":     err.Error(),
			}).Error("Failed to report procscan violation to admin")
		}
	}
}

func (s *Scanner) reportProcscanViolation(endpoint string, processInfo *models.ProcessInfo) error {
	detectedAt, err := time.Parse(time.RFC3339, processInfo.Timestamp)
	if err != nil {
		detectedAt = time.Now().UTC()
	}

	nodeName := currentNodeName()
	localizedMessage := localizeProcscanMessage(
		processInfo.Message,
		processInfo.ProcessName,
		processInfo.MatchType,
		processInfo.MatchRule,
	)
	var namespace *string
	if value := strings.TrimSpace(processInfo.Namespace); value != "" {
		namespace = &value
	}

	payload := procscanViolationRequest{
		EventID:           procscanEventID(processInfo, nodeName, detectedAt),
		Namespace:         namespace,
		PodName:           processInfo.PodName,
		PodUID:            processInfo.PodUID,
		ContainerID:       processInfo.ContainerID,
		NodeName:          nodeName,
		PID:               processInfo.PID,
		ProcessName:       processInfo.ProcessName,
		ProcessCommand:    processInfo.Command,
		MatchType:         processInfo.MatchType,
		MatchRule:         processInfo.MatchRule,
		RulesetRevision:   processInfo.RulesetRevision,
		PrimaryRuleID:     processInfo.PrimaryRuleID,
		MatchedRuleIDs:    append([]string{}, processInfo.MatchedRuleIDs...),
		Severity:          processInfo.Severity,
		RuleAction:        processInfo.RuleAction,
		AttributionStatus: processInfo.AttributionStatus,
		AttributionReason: processInfo.AttributionReason,
		Message:           localizedMessage,
		IsIllegal:         processInfo.IsIllegal,
		DetectedAt:        detectedAt,
		RawPayload: buildProcscanRawPayload(
			processInfo,
			nodeName,
			processInfo.MatchType,
			processInfo.MatchRule,
			localizedMessage,
			detectedAt,
		),
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.adminTimeout())
	defer cancel()

	return postJSON(ctx, endpoint, payload, s.adminBasicAuth())
}

func procscanEventID(processInfo *models.ProcessInfo, nodeName string, detectedAt time.Time) string {
	fingerprint := strings.Join([]string{
		strings.TrimSpace(processInfo.Namespace),
		strings.TrimSpace(processInfo.PodName),
		strings.TrimSpace(processInfo.PodUID),
		strings.TrimSpace(processInfo.ContainerID),
		strings.TrimSpace(nodeName),
		fmt.Sprintf("%d", processInfo.PID),
		strings.TrimSpace(processInfo.ProcessStartTime),
		fmt.Sprintf("%d", processInfo.RulesetRevision),
		strings.TrimSpace(processInfo.PrimaryRuleID),
		strings.TrimSpace(processInfo.MatchRule),
	}, "\x00")
	if strings.TrimSpace(processInfo.ProcessStartTime) == "" {
		fingerprint += "\x00" + detectedAt.UTC().Format(time.RFC3339Nano)
	}
	sum := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(sum[:])
}

func (s *Scanner) adminEndpoint() (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	baseURL := strings.TrimSpace(s.config.Notifications.Admin.BaseURL)
	if baseURL == "" {
		return "", false
	}

	return strings.TrimRight(baseURL, "/") + adminViolationsPath, true
}

func (s *Scanner) adminTimeout() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.config.Notifications.Admin.Timeout > 0 {
		return s.config.Notifications.Admin.Timeout
	}

	return defaultAdminTimeout
}

func (s *Scanner) adminBasicAuth() adminauth.BasicAuth {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return adminauth.FromValues(
		s.config.Notifications.Admin.BasicAuth.Username,
		s.config.Notifications.Admin.BasicAuth.Password,
	)
}

func postJSON(ctx context.Context, endpoint string, payload any, auth adminauth.BasicAuth) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	auth.Apply(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		bodyText := strings.TrimSpace(string(responseBody))
		if bodyText != "" {
			return fmt.Errorf("unexpected status %s: %s", resp.Status, bodyText)
		}

		return fmt.Errorf("unexpected status %s", resp.Status)
	}

	return nil
}

func buildProcscanRawPayload(
	processInfo *models.ProcessInfo,
	nodeName, matchType, matchRule, message string,
	detectedAt time.Time,
) map[string]any {
	return map[string]any{
		"进程信息": map[string]any{
			"进程ID":    processInfo.PID,
			"进程名称":    localizeUnknown(processInfo.ProcessName),
			"命令行":     localizeUnknown(processInfo.Command),
			"命中原因":    message,
			"Pod名称":   localizeUnknown(processInfo.PodName),
			"命名空间":    localizeUnknown(processInfo.Namespace),
			"容器ID":    localizeUnknown(processInfo.ContainerID),
			"Pod UID": localizeUnknown(processInfo.PodUID),
			"节点名称":    localizeUnknown(nodeName),
			"是否违规":    processInfo.IsIllegal,
			"检测时间":    detectedAt.Format(time.RFC3339),
			"匹配类型":    localizeMatchType(matchType),
			"匹配规则":    localizeUnknown(matchRule),
		},
		"上报来源": "procscan",
	}
}

func localizeProcscanMessage(message, processName, matchType, matchRule string) string {
	message = strings.TrimSpace(message)
	switch matchType {
	case "process_name":
		name := localizeUnknown(processName)
		rule := localizeUnknown(matchRule)
		return fmt.Sprintf("进程名 '%s' 命中黑名单规则 '%s'", name, rule)
	case "command_keyword":
		return fmt.Sprintf("命令行命中关键词黑名单规则 '%s'", localizeUnknown(matchRule))
	default:
		return message
	}
}

func localizeMatchType(matchType string) string {
	switch matchType {
	case "process_name":
		return "进程名"
	case "command_keyword":
		return "命令行关键词"
	default:
		return "未知"
	}
}

func localizeUnknown(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, "unknown") {
		return "未知"
	}

	return value
}

func currentNodeName() string {
	nodeName := strings.TrimSpace(os.Getenv("NODE_NAME"))
	if nodeName == "" {
		return "unknown"
	}

	return nodeName
}
