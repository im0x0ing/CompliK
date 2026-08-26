package procscanrule

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) GetRuleSet(c *gin.Context) {
	rules, err := h.service.GetRuleSet(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load procscan rules"})
		return
	}
	etag := revisionETag(rules.RulesetRevision)
	c.Header("ETag", etag)
	if strings.TrimSpace(c.GetHeader("If-None-Match")) == etag {
		c.Status(http.StatusNotModified)
		return
	}
	c.JSON(http.StatusOK, rules)
}

func (h *Handler) GetLegacyRuleSet(c *gin.Context) {
	rules, err := h.service.GetLegacyRuleSet(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to load legacy procscan rules"})
		return
	}
	c.JSON(http.StatusOK, rules)
}

func (h *Handler) GetRuntimeConfig(c *gin.Context) {
	runtimeConfig, err := h.service.GetRuntimeConfig(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"message": "procscan runtime config is unavailable"})
		return
	}
	c.JSON(http.StatusOK, runtimeConfig)
}

func (h *Handler) GetStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"v2_writes_enabled": h.service.V2WritesEnabled()})
}

func (h *Handler) UpdateRuleSet(c *gin.Context) {
	expectedRevision, err := parseRevisionETag(c.GetHeader("If-Match"))
	if err != nil {
		c.JSON(http.StatusPreconditionRequired, gin.H{"message": "If-Match ruleset revision is required"})
		return
	}
	var update RuleSetUpdate
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid procscan ruleset"})
		return
	}
	rules, err := h.service.UpdateRuleSet(c.Request.Context(), expectedRevision, update)
	if err != nil {
		h.respondWithError(c, err)
		return
	}
	c.Header("ETag", revisionETag(rules.RulesetRevision))
	c.JSON(http.StatusOK, rules)
}

func (h *Handler) ValidateRuleSet(c *gin.Context) {
	var update RuleSetUpdate
	if err := c.ShouldBindJSON(&update); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "invalid procscan ruleset"})
		return
	}
	if err := h.service.ValidateUpdate(update); err != nil {
		h.respondWithError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"valid": true})
}

func (h *Handler) respondWithError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrRevisionConflict):
		c.JSON(http.StatusConflict, gin.H{"message": err.Error()})
	case errors.Is(err, ErrV2WritesDisabled):
		c.JSON(http.StatusLocked, gin.H{"message": err.Error()})
	case errors.Is(err, ErrInvalidRuleSet):
		c.JSON(http.StatusBadRequest, gin.H{"message": err.Error()})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"message": "failed to update procscan rules"})
	}
}

func revisionETag(revision uint64) string {
	return `"` + strconv.FormatUint(revision, 10) + `"`
}

func parseRevisionETag(value string) (uint64, error) {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	if value == "" {
		return 0, errors.New("revision is required")
	}
	revision, err := strconv.ParseUint(value, 10, 64)
	if err != nil || revision == 0 {
		return 0, errors.New("invalid revision")
	}
	return revision, nil
}
