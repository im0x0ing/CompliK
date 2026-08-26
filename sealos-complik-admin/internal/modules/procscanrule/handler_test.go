package procscanrule

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestGetRuleSetReturnsETagOnNotModified(t *testing.T) {
	gin.SetMode(gin.TestMode)
	service := NewService(newFakeRepository(), false)
	handler := NewHandler(service)
	router := gin.New()
	router.GET("/api/procscan/rules", handler.GetRuleSet)

	first := httptest.NewRecorder()
	router.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api/procscan/rules", nil))
	if first.Code != http.StatusOK || first.Header().Get("ETag") != `"1"` {
		t.Fatalf("first response status=%d etag=%q", first.Code, first.Header().Get("ETag"))
	}

	request := httptest.NewRequest(http.MethodGet, "/api/procscan/rules", nil)
	request.Header.Set("If-None-Match", `"1"`)
	notModified := httptest.NewRecorder()
	router.ServeHTTP(notModified, request)
	if notModified.Code != http.StatusNotModified || notModified.Header().Get("ETag") != `"1"` {
		t.Fatalf("304 response status=%d etag=%q", notModified.Code, notModified.Header().Get("ETag"))
	}
}
