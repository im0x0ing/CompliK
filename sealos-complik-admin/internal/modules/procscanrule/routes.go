package procscanrule

import (
	"github.com/gin-gonic/gin"
	"sealos-complik-admin/internal/infra/config"
	"sealos-complik-admin/internal/infra/database"
)

func InitRoutes(g *gin.Engine, cfg config.ProcscanRulesConfig) *Service {
	service := NewService(NewRepository(database.Get()), cfg.V2WritesEnabled)
	handler := NewHandler(service)

	g.GET("/api/procscan/rules", handler.GetRuleSet)
	g.GET("/api/procscan/rules/legacy", handler.GetLegacyRuleSet)
	g.GET("/api/procscan/runtime-config", handler.GetRuntimeConfig)
	g.GET("/api/procscan/rules/status", handler.GetStatus)
	g.PUT("/api/procscan/rules", handler.UpdateRuleSet)
	g.POST("/api/procscan/rules/validate", handler.ValidateRuleSet)

	return service
}
