package config

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
)

func TestLoadRemoteUsesDedicatedEndpointsAndETag(t *testing.T) {
	var rulesRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, _ := r.BasicAuth()
		if username != "procscan" || password != "secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/api/procscan/runtime-config":
			_ = json.NewEncoder(w).Encode(map[string]string{"region": "cn", "webhook": "https://example.test/hook"})
		case "/api/procscan/rules":
			rulesRequests++
			if r.Header.Get("If-None-Match") == `"7"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"7"`)
			_ = json.NewEncoder(w).Encode(models.ProcscanRuleSet{
				SchemaVersion: 2, RulesetRevision: 7,
				Rules: []models.ProcscanRule{{
					ID: "miner", Name: "miner", Enabled: true,
					MatchType: "process_name", Pattern: "^xmrig$",
					Severity: "critical", Action: "ban",
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	loader := NewLoader(writeTestConfig(t, server.URL))
	config, err := loader.LoadLocal()
	if err != nil {
		t.Fatalf("LoadLocal() error = %v", err)
	}
	if err := loader.LoadRemote(context.Background(), config); err != nil {
		t.Fatalf("LoadRemote() first error = %v", err)
	}
	if err := loader.LoadRemote(context.Background(), config); err != nil {
		t.Fatalf("LoadRemote() second error = %v", err)
	}
	if rulesRequests != 2 || config.ProcscanRules.RulesetRevision != 7 {
		t.Fatalf("rules requests = %d, config = %+v", rulesRequests, config.ProcscanRules)
	}
	if config.Notifications.Region != "cn" || config.Notifications.Lark.Webhook == "" {
		t.Fatalf("runtime config not loaded: %+v", config.Notifications)
	}

	// A file-only reload starts with an empty ruleset. The ETag cache must still
	// restore the last valid rules when Admin answers 304 Not Modified.
	reloaded, err := loader.Load()
	if err != nil {
		t.Fatalf("Load() after ETag cache error = %v", err)
	}
	if reloaded.ProcscanRules.RulesetRevision != 7 {
		t.Fatalf("cached rules revision = %d, want 7", reloaded.ProcscanRules.RulesetRevision)
	}
}

func TestLoadRemoteFallsBackToDedicatedLegacyRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/procscan/runtime-config":
			_ = json.NewEncoder(w).Encode(map[string]string{"region": "cn", "webhook": "https://example.test/hook"})
		case "/api/procscan/rules":
			http.Error(w, "not found", http.StatusNotFound)
		case "/api/procscan/rules/legacy":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"blacklist": map[string]any{"processes": []string{"^xmrig$"}},
				"whitelist": map[string]any{"namespaces": []string{"^kube-system$"}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	loader := NewLoader(writeTestConfig(t, server.URL))
	config, err := loader.LoadLocal()
	if err != nil {
		t.Fatalf("LoadLocal() error = %v", err)
	}
	if err := loader.LoadRemote(context.Background(), config); err != nil {
		t.Fatalf("LoadRemote() error = %v", err)
	}
	if len(config.ProcscanRules.Rules) != 1 || config.ProcscanRules.Rules[0].Action != "alert" {
		t.Fatalf("legacy rules gained enforcement eligibility: %+v", config.ProcscanRules)
	}
}

func TestLoadRemoteKeepsLastRulesWhenV2TemporarilyFails(t *testing.T) {
	rulesHealthy := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/procscan/runtime-config":
			_ = json.NewEncoder(w).Encode(map[string]string{"region": "cn", "webhook": "https://example.test/hook"})
		case "/api/procscan/rules":
			if !rulesHealthy {
				http.Error(w, "temporary failure", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(models.ProcscanRuleSet{
				SchemaVersion: 2, RulesetRevision: 9,
				Rules: []models.ProcscanRule{{
					ID: "miner", Name: "miner", Enabled: true, MatchType: "process_name",
					Pattern: "^xmrig$", Severity: "critical", Action: "ban",
				}},
			})
		case "/api/procscan/rules/legacy":
			t.Fatal("temporary V2 failure must not fall back to legacy rules")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	loader := NewLoader(writeTestConfig(t, server.URL))
	config, err := loader.LoadLocal()
	if err != nil {
		t.Fatalf("LoadLocal() error = %v", err)
	}
	if err := loader.LoadRemote(context.Background(), config); err != nil {
		t.Fatalf("initial LoadRemote() error = %v", err)
	}
	rulesHealthy = false
	if err := loader.LoadRemote(context.Background(), config); err == nil {
		t.Fatal("LoadRemote() error = nil, want temporary failure")
	}
	if config.ProcscanRules.RulesetRevision != 9 || config.ProcscanRules.Rules[0].Action != "ban" {
		t.Fatalf("last valid rules changed: %+v", config.ProcscanRules)
	}
}

func TestLoadRemoteNotModifiedUsesNewerCachedRules(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/procscan/runtime-config":
			_ = json.NewEncoder(w).Encode(map[string]string{"region": "cn", "webhook": "https://example.test/hook"})
		case "/api/procscan/rules":
			if r.Header.Get("If-None-Match") == `"8"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"8"`)
			_ = json.NewEncoder(w).Encode(testRuleSet(8))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	loader := NewLoader(writeTestConfig(t, server.URL))
	stale, err := loader.LoadLocal()
	if err != nil {
		t.Fatalf("LoadLocal() error = %v", err)
	}
	stale.ProcscanRules = testRuleSet(7)

	newest, err := loader.LoadLocal()
	if err != nil {
		t.Fatalf("LoadLocal() error = %v", err)
	}
	if err := loader.LoadRemote(context.Background(), newest); err != nil {
		t.Fatalf("first LoadRemote() error = %v", err)
	}
	if err := loader.LoadRemote(context.Background(), stale); err != nil {
		t.Fatalf("stale LoadRemote() error = %v", err)
	}
	if stale.ProcscanRules.RulesetRevision != 8 {
		t.Fatalf("304 restored revision %d, want cached revision 8", stale.ProcscanRules.RulesetRevision)
	}
}

func testRuleSet(revision uint64) models.ProcscanRuleSet {
	return models.ProcscanRuleSet{
		SchemaVersion: 2, RulesetRevision: revision,
		Rules: []models.ProcscanRule{{
			ID: "miner", Name: "miner", Enabled: true,
			MatchType: "process_name", Pattern: "^xmrig$",
			Severity: "critical", Action: "ban",
		}},
	}
}

func writeTestConfig(t *testing.T, baseURL string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte("scanner:\n  proc_path: /proc\n  scan_interval: 1m\n  rules_refresh_interval: 30s\nnotifications:\n  admin:\n    base_url: " + baseURL + "\n    timeout: 2s\n    basic_auth:\n      username: procscan\n      password: secret\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
