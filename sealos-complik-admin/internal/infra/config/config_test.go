package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"sealos-complik-admin/internal/infra/config"
)

func TestLoadConfigAppliesDatabaseEnvOverrides(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")

	content := []byte(`port: 8081
database:
  host: file-host
  port: 3307
  username: file-user
  password: ""
  name: file-db
auth:
  realm: File Realm
`)
	if err := os.WriteFile(configPath, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("DB_HOST", "env-host")
	t.Setenv("DB_PORT", "3308")
	t.Setenv("DB_USERNAME", "root")
	t.Setenv("DB_PASSWORD", "env-password")
	t.Setenv("DB_NAME", "env-db")

	cfg := config.LoadConfig(configPath)

	if cfg.Database.Host != "env-host" {
		t.Fatalf("host = %q, want env-host", cfg.Database.Host)
	}

	if cfg.Database.Port != 3308 {
		t.Fatalf("port = %d, want 3308", cfg.Database.Port)
	}

	if cfg.Database.Username != "root" {
		t.Fatalf("username = %q, want root", cfg.Database.Username)
	}

	if cfg.Database.Password != "env-password" {
		t.Fatalf("password = %q, want env-password", cfg.Database.Password)
	}

	if cfg.Database.Name != "env-db" {
		t.Fatalf("name = %q, want env-db", cfg.Database.Name)
	}
}

func TestLoadConfigAppliesProcscanAuthAndRuleWriteOverrides(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	content := []byte(`port: 8081
auth:
  enabled: true
  username: admin
  password: admin-password
procscan_auth:
  enabled: false
procscan_rules:
  v2_writes_enabled: false
`)
	if err := os.WriteFile(configPath, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("PROCSCAN_BASIC_AUTH_ENABLED", "true")
	t.Setenv("PROCSCAN_BASIC_AUTH_USERNAME", "procscan")
	t.Setenv("PROCSCAN_BASIC_AUTH_PASSWORD", "procscan-password")
	t.Setenv("PROCSCAN_RULES_V2_WRITES_ENABLED", "true")

	cfg := config.LoadConfig(configPath)
	if !cfg.ProcscanAuth.Enabled || cfg.ProcscanAuth.Username != "procscan" ||
		cfg.ProcscanAuth.Password != "procscan-password" {
		t.Fatalf("unexpected procscan auth: %+v", cfg.ProcscanAuth)
	}
	if !cfg.ProcscanRules.V2WritesEnabled {
		t.Fatal("V2WritesEnabled = false, want true")
	}
}
