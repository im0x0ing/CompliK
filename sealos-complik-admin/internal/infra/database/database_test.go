package database_test

import (
	"strings"
	"testing"

	"sealos-complik-admin/internal/infra/config"
	"sealos-complik-admin/internal/infra/database"
)

const maxDatabaseNameLength = 64

func TestValidateConfigAcceptsDatabaseNames(t *testing.T) {
	tests := []string{
		"sealos-complik-admin",
		"sealos_complik_admin",
		"CompliK2026",
		strings.Repeat("a", maxDatabaseNameLength),
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validDatabaseConfig()
			cfg.Name = name

			if err := validateConfig(cfg); err != nil {
				t.Fatalf("validateConfig() error = %v", err)
			}
		})
	}
}

func TestValidateConfigRejectsDatabaseNames(t *testing.T) {
	tests := []string{
		"sealos complik",
		"sealos`complik",
		"sealos.complik",
		"sealos/complik",
		strings.Repeat("a", maxDatabaseNameLength+1),
	}

	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validDatabaseConfig()
			cfg.Name = name

			if err := validateConfig(cfg); err == nil {
				t.Fatal("validateConfig() error = nil")
			}
		})
	}
}

func validDatabaseConfig() config.DatabaseConfig {
	return config.DatabaseConfig{
		Host:     "localhost",
		Port:     3306,
		Username: "root",
		Password: "test-password",
		Name:     "sealos-complik-admin",
	}
}

func validateConfig(cfg config.DatabaseConfig) error {
	return database.ValidateConfig(cfg)
}
