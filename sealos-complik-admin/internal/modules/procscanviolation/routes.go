package procscanviolation

import (
	"github.com/gin-gonic/gin"
	"sealos-complik-admin/internal/infra/database"
	"sealos-complik-admin/internal/modules/autoban"
	"sealos-complik-admin/internal/modules/procscanrule"
)

func InitRoutes(
	g *gin.Engine,
	autobanHandler autoban.DecisionHandler,
	ruleService *procscanrule.Service,
	verifier AttributionVerifier,
) *Service {
	repository := NewRepository(database.Get())
	service := NewService(repository, autobanHandler, ruleService, verifier)
	handler := NewHandler(service)

	g.POST("/api/procscan-violations", handler.CreateViolation)
	g.DELETE("/api/procscan-violations/id/:id", handler.DeleteViolationByID)
	g.DELETE("/api/procscan-violations/:namespace", handler.DeleteViolations)
	g.GET("/api/procscan-violations/:namespace", handler.GetViolations)
	g.GET("/api/procscan-violations", handler.ListViolations)
	g.GET("/api/namespaces/:namespace/procscan-violations-status", handler.GetViolationStatus)

	return service
}
