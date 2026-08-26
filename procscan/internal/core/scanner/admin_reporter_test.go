package scanner

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
)

func TestReportProcscanViolationSendsStructuredMatchAndNullNamespace(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	scanner := NewScanner(&models.Config{Notifications: models.NotificationsConfig{
		Admin: models.AdminNotificationConfig{BaseURL: server.URL, Timeout: time.Second},
	}})
	info := &models.ProcessInfo{
		PID: 42, ProcessName: "xmrig", Command: "xmrig --url pool",
		Timestamp: time.Now().UTC().Format(time.RFC3339), Message: "process matched rule miner-xmrig",
		IsIllegal: true, RulesetRevision: 7, PrimaryRuleID: "miner-xmrig",
		MatchedRuleIDs: []string{"miner-xmrig", "generic-miner"}, MatchType: "process_name",
		MatchRule: "(?i)^xmrig$", Severity: "critical", RuleAction: "ban",
		AttributionStatus: "unresolved", AttributionReason: "cri_lookup_failed",
	}

	if err := scanner.reportProcscanViolation(server.URL+adminViolationsPath, info); err != nil {
		t.Fatalf("reportProcscanViolation() error = %v", err)
	}
	if payload["namespace"] != nil {
		t.Fatalf("namespace = %#v, want null", payload["namespace"])
	}
	if payload["primary_rule_id"] != "miner-xmrig" || payload["ruleset_revision"] != float64(7) {
		t.Fatalf("structured fields missing: %#v", payload)
	}
	if payload["attribution_status"] != "unresolved" || payload["attribution_reason"] != "cri_lookup_failed" {
		t.Fatalf("attribution fields missing: %#v", payload)
	}
	if payload["event_id"] == "" {
		t.Fatal("event_id is empty")
	}
}

func TestProcscanEventIDUsesProcessStartTimeForDeduplication(t *testing.T) {
	info := &models.ProcessInfo{
		PID:              42,
		ProcessName:      "xmrig",
		Command:          "xmrig --url pool",
		PodUID:           "pod-uid",
		ProcessStartTime: "12345",
		RulesetRevision:  7,
		PrimaryRuleID:    "miner-xmrig",
		MatchRule:        "(?i)^xmrig$",
	}
	first := procscanEventID(info, "node-a", time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC))
	second := procscanEventID(info, "node-a", time.Date(2026, 8, 16, 10, 5, 0, 0, time.UTC))
	if first != second {
		t.Fatalf("event ID changed with detected time: %q != %q", first, second)
	}

	info.ProcessStartTime = "12346"
	if changed := procscanEventID(info, "node-a", time.Now().UTC()); changed == first {
		t.Fatal("event ID did not change when process start time changed")
	}
}

func TestProcscanEventIDFallsBackToDetectedTimeWithoutProcessStartTime(t *testing.T) {
	info := &models.ProcessInfo{
		PID:             42,
		ProcessName:     "xmrig",
		Command:         "xmrig --url pool",
		RulesetRevision: 7,
		PrimaryRuleID:   "miner-xmrig",
		MatchRule:       "(?i)^xmrig$",
	}
	first := procscanEventID(info, "node-a", time.Date(2026, 8, 16, 10, 0, 0, 0, time.UTC))
	second := procscanEventID(info, "node-a", time.Date(2026, 8, 16, 10, 5, 0, 0, time.UTC))
	if first == second {
		t.Fatal("event ID did not change when detected time changed without process start time")
	}
}
