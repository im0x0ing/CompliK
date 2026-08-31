package scanner

import (
	"testing"

	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
)

func TestStopAdminReporterDoesNotCloseQueue(t *testing.T) {
	s := &Scanner{
		reportQueue:   make(chan *models.ProcessInfo, 1),
		reportStarted: true,
	}
	queue := s.reportQueue

	s.stopAdminReporter()

	select {
	case queue <- &models.ProcessInfo{PID: 1}:
	default:
		t.Fatal("expected queue handle to remain send-safe after reporter stop")
	}
}
