package router

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"sealos-complik-admin/internal/infra/config"
	"sealos-complik-admin/internal/infra/database"
	"sealos-complik-admin/internal/infra/k8s"
	"sealos-complik-admin/internal/middleware"
	"sealos-complik-admin/internal/modules/autoban"
	"sealos-complik-admin/internal/modules/ban"
	"sealos-complik-admin/internal/modules/commitment"
	"sealos-complik-admin/internal/modules/complikviolation"
	"sealos-complik-admin/internal/modules/discoveredpath"
	"sealos-complik-admin/internal/modules/procscanrule"
	"sealos-complik-admin/internal/modules/procscanviolation"
	"sealos-complik-admin/internal/modules/projectconfig"
	"sealos-complik-admin/internal/modules/unban"
)

type App struct {
	Engine   *gin.Engine
	Shutdown func(context.Context)
}

func InitRouter(cfg *config.Config) (*App, error) {
	g := gin.Default()
	g.GET("/health", HealthCheck)
	if err := validateAuthConfig(cfg); err != nil {
		return nil, err
	}

	locker := buildNamespaceLocker()
	readinessChecker, ok := locker.(readinessChecker)
	if !ok {
		return nil, errors.New("namespace locker does not support readiness checks")
	}
	g.GET("/ready", readinessHandler(database.CheckReady, readinessChecker))

	if cfg.Auth.Enabled {
		g.Use(middleware.RoleBasedBasicAuth(cfg.Auth, cfg.ProcscanAuth))
	}

	banService, err := ban.InitBanRoutes(g, cfg, locker)
	if err != nil {
		return nil, fmt.Errorf("init ban routes: %w", err)
	}

	autobanService := autoban.NewService(projectconfig.NewRepository(database.Get()), banService)

	complikviolation.InitRoutes(g, autobanService)
	discoveredpath.InitRoutes(g)

	if err := commitment.InitCommitmentRoutes(g, cfg); err != nil {
		return nil, fmt.Errorf("init commitment routes: %w", err)
	}

	projectconfig.InitProjectConfigRoutes(g)
	procscanRuleService := procscanrule.InitRoutes(g, cfg.ProcscanRules)
	var attributionVerifier procscanviolation.AttributionVerifier
	if verifier, ok := locker.(procscanviolation.AttributionVerifier); ok {
		attributionVerifier = verifier
	}
	procscanService := procscanviolation.InitRoutes(g, autobanService, procscanRuleService, attributionVerifier)

	if _, err := unban.InitUnbanRoutes(g, locker); err != nil {
		return nil, fmt.Errorf("init unban routes: %w", err)
	}

	reconcilerCtx, reconcilerCancel := context.WithCancel(context.Background())
	banService.StartLabelReconciler(reconcilerCtx, 0)
	procscanService.StartAutobanRetryReconciler(reconcilerCtx, 0)

	return &App{
		Engine: g,
		Shutdown: func(context.Context) {
			reconcilerCancel()
		},
	}, nil
}

func validateAuthConfig(cfg *config.Config) error {
	if cfg == nil {
		return errors.New("config is required")
	}
	if cfg.ProcscanAuth.Enabled && !cfg.Auth.Enabled {
		return errors.New("admin basic auth must be enabled when procscan auth is enabled")
	}
	if !cfg.Auth.Enabled {
		return nil
	}
	adminUsername := strings.TrimSpace(cfg.Auth.Username)
	adminPassword := strings.TrimSpace(cfg.Auth.Password)
	if adminUsername == "" || adminPassword == "" {
		return errors.New("basic auth username and password are required")
	}
	if !cfg.ProcscanAuth.Enabled {
		return nil
	}
	procscanUsername := strings.TrimSpace(cfg.ProcscanAuth.Username)
	procscanPassword := strings.TrimSpace(cfg.ProcscanAuth.Password)
	if procscanUsername == "" || procscanPassword == "" {
		return errors.New("procscan basic auth username and password are required")
	}
	if adminUsername == procscanUsername && adminPassword == procscanPassword {
		return errors.New("procscan and admin basic auth credentials must be different")
	}
	return nil
}

func buildNamespaceLocker() k8s.NamespaceLocker {
	locker, err := k8s.NewNamespaceLocker()
	if err != nil {
		log.Printf("namespace locker disabled: %v", err)
		return k8s.NewNoopNamespaceLocker()
	}

	return locker
}

func HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "All is well",
	})
}

type readinessChecker interface {
	CheckReady(context.Context) error
}

func readinessHandler(
	checkDatabase func(context.Context) error,
	locker readinessChecker,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()

		if checkDatabase == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"message": "service is not ready",
			})
			return
		}

		if err := checkDatabase(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"message": "service is not ready",
			})
			return
		}

		if locker == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"message": "service is not ready",
			})
			return
		}

		if err := locker.CheckReady(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"message": "service is not ready",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "service is ready",
		})
	}
}
