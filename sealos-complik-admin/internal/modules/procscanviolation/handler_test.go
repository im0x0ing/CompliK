package procscanviolation

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCreateViolationRejectsOversizedBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	body := append([]byte(`{"process_name":"xmrig","process_command":"`), bytes.Repeat([]byte("x"), 1<<20)...)
	body = append(body, []byte(`","message":"matched","pid":1}`)...)

	request := httptest.NewRequest(http.MethodPost, "/api/procscan-violations", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = request

	NewHandler(nil).CreateViolation(ctx)

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusRequestEntityTooLarge)
	}
}
