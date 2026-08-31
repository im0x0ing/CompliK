package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"sealos-complik-admin/internal/infra/config"
)

const (
	pingTimeout           = 5 * time.Second
	maxDatabaseNameLength = 64
	maxOpenConnections    = 25
	maxIdleConnections    = 5
	connectionMaxLifetime = 30 * time.Minute
	connectionMaxIdleTime = 5 * time.Minute
)

var client *gorm.DB

// Init initializes the shared MySQL connection and verifies it is reachable.
func Init(cfg config.DatabaseConfig) (*gorm.DB, error) {
	if client != nil {
		return client, nil
	}
	// verify config before trying to connect to avoid unnecessary connection attempts with invalid config
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	// Create database if it does not exist
	if err := createDatabase(cfg); err != nil {
		return nil, err
	}

	// Open connection to the newly created database and verify it is reachable
	db, err := open(DSN(cfg))
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}

	client = db

	return client, nil
}

// createDatabase creates the configured database if it does not already exist.
func createDatabase(cfg config.DatabaseConfig) error {
	db, err := open(serverDSN(cfg))
	if err != nil {
		return fmt.Errorf("connect mysql server: %w", err)
	}

	defer func() {
		_ = closeDB(db)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()

	query := createDatabaseQuery(cfg.Name)
	if err := db.WithContext(ctx).Exec(query).Error; err != nil {
		return fmt.Errorf("create database %q: %w", cfg.Name, err)
	}

	return nil
}

// Get returns the initialized shared database connection.
func Get() *gorm.DB {
	return client
}

// Close closes the shared database connection if it has been initialized.
func Close() error {
	if client == nil {
		return nil
	}

	db := client
	client = nil

	if err := closeDB(db); err != nil {
		return fmt.Errorf("close database: %w", err)
	}

	return nil
}

// CloseWithReport closes the shared connection and reports any error through logf.
func CloseWithReport(logf func(string, ...any)) {
	if err := Close(); err != nil && logf != nil {
		logf("%v", err)
	}
}

// DSN builds the MySQL data source name from application config.
func DSN(cfg config.DatabaseConfig) string {
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Name,
	)
}

// serverDSN builds a MySQL data source name without selecting a database first.
func serverDSN(cfg config.DatabaseConfig) string {
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.Username,
		cfg.Password,
		cfg.Host,
		cfg.Port,
	)
}

// ValidateConfig checks the minimum fields required to build a valid MySQL DSN.
func ValidateConfig(cfg config.DatabaseConfig) error {
	if cfg.Host == "" {
		return errors.New("database host is required")
	}

	if cfg.Port <= 0 || cfg.Port > 65535 {
		return fmt.Errorf("database port %d is invalid", cfg.Port)
	}

	if cfg.Username == "" {
		return errors.New("database username is required")
	}

	if strings.TrimSpace(cfg.Password) == "" {
		return errors.New("database password is required")
	}

	if cfg.Name == "" {
		return errors.New("database name is required")
	}

	if err := validateDatabaseName(cfg.Name); err != nil {
		return err
	}

	return nil
}

func validateDatabaseName(name string) error {
	if len(name) > maxDatabaseNameLength {
		return fmt.Errorf("database name %q exceeds %d characters", name, maxDatabaseNameLength)
	}

	for _, r := range name {
		if isDatabaseNameChar(r) {
			continue
		}

		return fmt.Errorf("database name %q contains invalid character %q", name, r)
	}

	return nil
}

func isDatabaseNameChar(r rune) bool {
	return r >= 'a' && r <= 'z' ||
		r >= 'A' && r <= 'Z' ||
		r >= '0' && r <= '9' ||
		r == '_' ||
		r == '-'
}

func createDatabaseQuery(name string) string {
	return "CREATE DATABASE IF NOT EXISTS " + quoteIdentifier(name) +
		" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
}

func open(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open gorm connection: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql db: %w", err)
	}
	sqlDB.SetMaxOpenConns(maxOpenConnections)
	sqlDB.SetMaxIdleConns(maxIdleConnections)
	sqlDB.SetConnMaxLifetime(connectionMaxLifetime)
	sqlDB.SetConnMaxIdleTime(connectionMaxIdleTime)

	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("ping mysql: %w", err)
	}

	return db, nil
}

func closeDB(db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("get sql db: %w", err)
	}

	return sqlDB.Close()
}

func quoteIdentifier(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}
