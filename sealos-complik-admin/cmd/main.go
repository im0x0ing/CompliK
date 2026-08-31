package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sealos-complik-admin/internal/infra/config"
	"sealos-complik-admin/internal/infra/database"
	"sealos-complik-admin/internal/infra/migration"
	"sealos-complik-admin/internal/router"
)

const (
	defaultConfigFile  = "/config/config.yaml"
	fallbackConfigFile = "configs/config.yaml"
)

func resolveConfigFile() string {
	if value := strings.TrimSpace(os.Getenv("CONFIG_FILE")); value != "" {
		return value
	}

	if _, err := os.Stat(defaultConfigFile); err == nil {
		return defaultConfigFile
	}

	return fallbackConfigFile
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg := config.LoadConfig(resolveConfigFile())

	if _, err := database.Init(cfg.Database); err != nil {
		return fmt.Errorf("initialize database: %w", err)
	}

	defer database.CloseWithReport(log.Printf)

	if err := migration.AutoMigrate(database.Get()); err != nil {
		return fmt.Errorf("auto migrate tables: %w", err)
	}

	app, err := router.InitRouter(cfg)
	if err != nil {
		return fmt.Errorf("initialize router: %w", err)
	}

	addr := fmt.Sprintf(":%d", cfg.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: app.Engine,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("server listening on %s", addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("run server: %w", err)
		}
	case sig := <-stop:
		log.Printf("received signal %s, shutting down", sig)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	app.Shutdown(shutdownCtx)

	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown server: %w", err)
	}

	return nil
}
