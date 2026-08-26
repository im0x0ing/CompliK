package middleware

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"sealos-complik-admin/internal/infra/config"
)

type IdentityRole string

const (
	IdentityRoleAdmin    IdentityRole = "admin"
	IdentityRoleProcscan IdentityRole = "procscan"
	identityRoleKey                   = "identity_role"
)

func BasicAuth(cfg config.AuthConfig) gin.HandlerFunc {
	username := strings.TrimSpace(cfg.Username)
	password := strings.TrimSpace(cfg.Password)

	realm := strings.TrimSpace(cfg.Realm)
	if realm == "" {
		realm = "CompliK Admin"
	}

	return func(c *gin.Context) {
		if isPublicProbe(c.Request.Method, c.Request.URL.Path) {
			c.Next()
			return
		}

		requestUsername, requestPassword, ok := c.Request.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(requestUsername), []byte(username)) != 1 ||
			subtle.ConstantTimeCompare([]byte(requestPassword), []byte(password)) != 1 {
			c.Header("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q`, realm))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorized",
			})

			return
		}

		c.Next()
	}
}

// RoleBasedBasicAuth accepts admin credentials everywhere and limits Procscan
// credentials to runtime reads and violation ingestion.
func RoleBasedBasicAuth(admin, procscan config.AuthConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if isPublicProbe(c.Request.Method, c.Request.URL.Path) {
			c.Next()
			return
		}

		username, password, ok := c.Request.BasicAuth()
		if !ok {
			abortUnauthorized(c, admin.Realm)
			return
		}

		switch {
		case credentialsMatch(username, password, admin):
			c.Set(identityRoleKey, IdentityRoleAdmin)
			c.Next()
		case procscan.Enabled && credentialsMatch(username, password, procscan):
			if !isProcscanRouteAllowed(c.Request.Method, c.Request.URL.Path) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"message": "forbidden"})
				return
			}
			c.Set(identityRoleKey, IdentityRoleProcscan)
			c.Next()
		default:
			abortUnauthorized(c, admin.Realm)
		}
	}
}

func IdentityRoleFromContext(c *gin.Context) IdentityRole {
	if c == nil {
		return ""
	}
	role, _ := c.Get(identityRoleKey)
	typed, _ := role.(IdentityRole)
	return typed
}

func credentialsMatch(username, password string, cfg config.AuthConfig) bool {
	return subtle.ConstantTimeCompare([]byte(username), []byte(strings.TrimSpace(cfg.Username))) == 1 &&
		subtle.ConstantTimeCompare([]byte(password), []byte(strings.TrimSpace(cfg.Password))) == 1
}

func isPublicProbe(method, path string) bool {
	return method == http.MethodGet && (path == "/health" || path == "/ready")
}

func isProcscanRouteAllowed(method, path string) bool {
	if method == http.MethodPost && path == "/api/procscan-violations" {
		return true
	}
	if method != http.MethodGet {
		return false
	}
	return path == "/api/procscan/rules" ||
		path == "/api/procscan/rules/legacy" ||
		path == "/api/procscan/runtime-config"
}

func abortUnauthorized(c *gin.Context, realm string) {
	realm = strings.TrimSpace(realm)
	if realm == "" {
		realm = "CompliK Admin"
	}
	c.Header("WWW-Authenticate", fmt.Sprintf(`Basic realm=%q`, realm))
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "unauthorized"})
}
