package health

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadinessTracksRulesAvailability(t *testing.T) {
	ready := false
	server := NewServer(8081, func() bool { return ready })

	request := func(path string) int {
		recorder := httptest.NewRecorder()
		server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		return recorder.Code
	}

	if status := request("/healthz"); status != http.StatusOK {
		t.Fatalf("health status = %d", status)
	}
	if status := request("/readyz"); status != http.StatusServiceUnavailable {
		t.Fatalf("not-ready status = %d", status)
	}
	ready = true
	if status := request("/readyz"); status != http.StatusOK {
		t.Fatalf("ready status = %d", status)
	}
}
