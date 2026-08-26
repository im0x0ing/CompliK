package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"sealos-complik-admin/internal/infra/config"
)

func TestValidateAuthConfigRejectsSharedAdminAndProcscanCredentials(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled: true, Username: "shared", Password: "shared-password",
		},
		ProcscanAuth: config.AuthConfig{
			Enabled: true, Username: "shared", Password: "shared-password",
		},
	}

	if err := validateAuthConfig(cfg); err == nil {
		t.Fatal("validateAuthConfig() error = nil, want shared credential rejection")
	}
}

func TestValidateAuthConfigAllowsSeparateCredentials(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Enabled: true, Username: "admin", Password: "admin-password",
		},
		ProcscanAuth: config.AuthConfig{
			Enabled: true, Username: "procscan", Password: "procscan-password",
		},
	}

	if err := validateAuthConfig(cfg); err != nil {
		t.Fatalf("validateAuthConfig() error = %v", err)
	}
}

type fakeReadinessChecker struct {
	err error
}

func (f fakeReadinessChecker) CheckReady(context.Context) error {
	return f.err
}

func TestReadinessHandlerReportsDependencyState(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		dbErr      error
		lockerErr  error
		wantStatus int
	}{
		{name: "ready", wantStatus: http.StatusOK},
		{name: "database unavailable", dbErr: context.DeadlineExceeded, wantStatus: http.StatusServiceUnavailable},
		{name: "kubernetes unavailable", lockerErr: context.DeadlineExceeded, wantStatus: http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.GET("/ready", readinessHandler(
				func(context.Context) error { return tt.dbErr },
				fakeReadinessChecker{err: tt.lockerErr},
			))

			resp := httptest.NewRecorder()
			router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/ready", nil))

			if resp.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", resp.Code, tt.wantStatus)
			}
		})
	}
}
