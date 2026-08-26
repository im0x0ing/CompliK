package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"sealos-complik-admin/internal/infra/config"
)

func TestRoleBasedBasicAuthLimitsProcscanIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RoleBasedBasicAuth(
		config.AuthConfig{Enabled: true, Username: "admin", Password: "admin-password"},
		config.AuthConfig{Enabled: true, Username: "procscan", Password: "procscan-password"},
	))
	router.GET("/api/procscan/rules", func(c *gin.Context) { c.Status(http.StatusOK) })
	router.PUT("/api/procscan/rules", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	router.POST("/api/procscan-violations", func(c *gin.Context) { c.Status(http.StatusCreated) })

	tests := []struct {
		name       string
		method     string
		path       string
		username   string
		password   string
		wantStatus int
	}{
		{name: "procscan reads rules", method: http.MethodGet, path: "/api/procscan/rules", username: "procscan", password: "procscan-password", wantStatus: http.StatusOK},
		{name: "procscan reports violation", method: http.MethodPost, path: "/api/procscan-violations", username: "procscan", password: "procscan-password", wantStatus: http.StatusCreated},
		{name: "procscan cannot write rules", method: http.MethodPut, path: "/api/procscan/rules", username: "procscan", password: "procscan-password", wantStatus: http.StatusForbidden},
		{name: "admin writes rules", method: http.MethodPut, path: "/api/procscan/rules", username: "admin", password: "admin-password", wantStatus: http.StatusNoContent},
		{name: "unknown identity rejected", method: http.MethodGet, path: "/api/procscan/rules", username: "unknown", password: "bad", wantStatus: http.StatusUnauthorized},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.SetBasicAuth(tc.username, tc.password)
			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, req)
			if resp.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", resp.Code, tc.wantStatus)
			}
		})
	}
}
