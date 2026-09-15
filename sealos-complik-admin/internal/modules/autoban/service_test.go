//nolint:testpackage // Tests exercise unexported policy loading and service helpers.
package autoban

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"sealos-complik-admin/internal/modules/ban"
	"sealos-complik-admin/internal/modules/projectconfig"
)

type fakeBanService struct {
	status           *ban.BanStatusResponse
	createReqs       []ban.CreateBanRequest
	statusNamespaces []string
	createErr        error
	statusErr        error
}

type fakePolicyRepository struct {
	configs []projectconfig.ProjectConfig
	err     error
	calls   int
}

func (f *fakeBanService) CreateBan(ctx context.Context, req ban.CreateBanRequest) error {
	f.createReqs = append(f.createReqs, req)
	return f.createErr
}

func (f *fakeBanService) GetBanStatus(
	ctx context.Context,
	namespace string,
) (*ban.BanStatusResponse, error) {
	f.statusNamespaces = append(f.statusNamespaces, namespace)
	if f.statusErr != nil {
		return nil, f.statusErr
	}

	if f.status == nil {
		return &ban.BanStatusResponse{Banned: false}, nil
	}

	return f.status, nil
}

func (f *fakePolicyRepository) ListProjectConfigsByType(
	ctx context.Context,
	configType string,
) ([]projectconfig.ProjectConfig, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}

	return f.configs, nil
}

func TestHandleViolationCreatesBan(t *testing.T) {
	fake := &fakeBanService{}
	svc := NewService(policyRepo(`{
		"enabled": true,
		"dryRun": false,
		"operatorName": "system/autoban",
		"sources": {
			"procscan": { "enabled": true }
		},
		"processNameAllowlist": ["xmrig"]
	}`), fake)
	fixed := time.Date(2026, time.July, 29, 8, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return fixed }

	err := svc.HandleViolation(context.Background(), Violation{
		Namespace:    "  ns-demo  ",
		Source:       SourceProcscan,
		ProcessName:  "xmrig",
		DetectorName: "miner-rule",
		Summary:      "suspicious command",
		Detail:       "process_command=xmrig --url ...",
		IsIllegal:    true,
		DetectedAt:   fixed,
	})
	if err != nil {
		t.Fatalf("HandleViolation returned error: %v", err)
	}

	if len(fake.createReqs) != 1 {
		t.Fatalf("expected 1 ban request, got %d", len(fake.createReqs))
	}

	req := fake.createReqs[0]
	if req.Namespace != "ns-demo" {
		t.Fatalf("unexpected namespace: %q", req.Namespace)
	}

	if req.OperatorName != "system/autoban" {
		t.Fatalf("unexpected operator name: %q", req.OperatorName)
	}

	if !req.BanStartTime.Equal(fixed) {
		t.Fatalf("unexpected ban start time: %v", req.BanStartTime)
	}

	if got := req.Reason; !strings.Contains(got, "Admin auto-ban") ||
		!strings.Contains(got, "procscan") ||
		!strings.Contains(got, "suspicious command") {
		t.Fatalf("unexpected ban reason: %q", got)
	}
}

func TestHandleViolationDoesNotBanComplikContent(t *testing.T) {
	fake := &fakeBanService{}
	svc := NewService(policyRepo(`{
		"enabled": true,
		"dryRun": false,
		"operatorName": "system/autoban",
		"sources": {
			"complik": { "enabled": true }
		},
		"processNameAllowlist": ["xmrig"]
	}`), fake)

	err := svc.HandleViolation(context.Background(), Violation{
		Namespace:    "ns-demo",
		Source:       SourceComplik,
		DetectorName: "keyword-rule",
		Summary:      "blocked content detected",
		IsIllegal:    true,
	})
	if err != nil {
		t.Fatalf("HandleViolation returned error: %v", err)
	}

	if len(fake.createReqs) != 0 {
		t.Fatalf("content violation was submitted for ban: %+v", fake.createReqs)
	}
}

func TestHandleViolationHonorsProcessNamePolicy(t *testing.T) {
	fake := &fakeBanService{}
	svc := NewService(policyRepo(`{
		"enabled": true,
		"dryRun": false,
		"sources": {
			"procscan": { "enabled": true }
		},
		"processNameAllowlist": ["xmrig"],
		"processNameDenylist": ["systemd"]
	}`), fake)

	err := svc.HandleViolation(context.Background(), Violation{
		Namespace:    "ns-demo",
		Source:       SourceProcscan,
		ProcessName:  "xmrig",
		DetectorName: "miner-rule",
		IsIllegal:    true,
	})
	if err != nil {
		t.Fatalf("HandleViolation returned error: %v", err)
	}

	err = svc.HandleViolation(context.Background(), Violation{
		Namespace:    "ns-demo",
		Source:       SourceProcscan,
		ProcessName:  "nginx",
		DetectorName: "web-rule",
		IsIllegal:    true,
	})
	if err != nil {
		t.Fatalf("HandleViolation returned error: %v", err)
	}

	err = svc.HandleViolation(context.Background(), Violation{
		Namespace:    "ns-demo",
		Source:       SourceProcscan,
		ProcessName:  "systemd",
		DetectorName: "system-rule",
		IsIllegal:    true,
	})
	if err != nil {
		t.Fatalf("HandleViolation returned error: %v", err)
	}

	if len(fake.createReqs) != 1 {
		t.Fatalf("expected 1 ban request, got %d", len(fake.createReqs))
	}

	if len(fake.statusNamespaces) != 1 {
		t.Fatalf("expected 1 ban status check, got %d", len(fake.statusNamespaces))
	}
}

func TestHandleViolationRejectsEmptyProcessAllowlistEvenWhenRuleValidated(t *testing.T) {
	fake := &fakeBanService{}
	svc := NewService(policyRepo(`{
		"enabled": true,
		"dryRun": false,
		"sources": { "procscan": { "enabled": true } }
	}`), fake)

	decision, err := svc.HandleViolationDecision(context.Background(), Violation{
		Namespace:     "ns-demo",
		Source:        SourceProcscan,
		ProcessName:   "xmrig",
		RuleValidated: true,
		IsIllegal:     true,
	})
	if err != nil {
		t.Fatalf("HandleViolationDecision returned error: %v", err)
	}
	if decision.Status != DecisionNotTriggered || decision.Reason != "process_policy_rejected" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	if len(fake.createReqs) != 0 {
		t.Fatalf("empty process allowlist was submitted for ban: %+v", fake.createReqs)
	}
}

func TestHandleViolationMatchesWrappedProcessPattern(t *testing.T) {
	fake := &fakeBanService{}
	svc := NewService(policyRepo(`{
		"enabled": true,
		"dryRun": false,
		"sources": { "procscan": { "enabled": true } },
		"processNameAllowlist": ["(?i)^xmrig$"]
	}`), fake)

	if err := svc.HandleViolation(context.Background(), Violation{
		Namespace:   "ns-demo",
		Source:      SourceProcscan,
		ProcessName: "XMRIG",
		IsIllegal:   true,
	}); err != nil {
		t.Fatalf("HandleViolation returned error: %v", err)
	}
	if len(fake.createReqs) != 1 {
		t.Fatalf("expected 1 ban request, got %d", len(fake.createReqs))
	}
}

func TestHandleViolationUsesConservativeDefaultPolicy(t *testing.T) {
	fake := &fakeBanService{}
	svc := NewService(nil, fake)

	err := svc.HandleViolation(context.Background(), Violation{
		Namespace:    "ns-demo",
		Source:       SourceProcscan,
		DetectorName: "miner-rule",
		IsIllegal:    true,
	})
	if err != nil {
		t.Fatalf("HandleViolation returned error: %v", err)
	}

	if len(fake.statusNamespaces) != 0 {
		t.Fatalf("expected no ban status checks, got %d", len(fake.statusNamespaces))
	}

	if len(fake.createReqs) != 0 {
		t.Fatalf("expected no ban request, got %d", len(fake.createReqs))
	}
}

func TestHandleViolationReportsUnavailableBanServiceAsFailure(t *testing.T) {
	svc := NewService(policyRepo(`{
		"enabled": true,
		"dryRun": false,
		"sources": { "procscan": { "enabled": true } },
		"processNameAllowlist": ["xmrig"]
	}`), nil)

	decision, err := svc.HandleViolationDecision(context.Background(), Violation{
		Namespace:    "ns-demo",
		Source:       SourceProcscan,
		DetectorName: "miner-rule",
		IsIllegal:    true,
	})
	if err == nil {
		t.Fatal("expected unavailable ban service error")
	}
	if decision.Status != DecisionFailed || decision.Reason != "ban_service_unavailable" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}

func TestHandleViolationRejectsNonTenantNamespaces(t *testing.T) {
	fake := &fakeBanService{}
	svc := NewService(policyRepo(`{
		"enabled": true,
		"dryRun": false,
		"sources": { "procscan": { "enabled": true } }
	}`), fake)

	for _, namespace := range []string{"default", "ingress-nginx", "kube-system", "demo-ns"} {
		if err := svc.HandleViolation(context.Background(), Violation{
			Namespace: namespace,
			Source:    SourceProcscan,
			IsIllegal: true,
		}); err != nil {
			t.Fatalf("HandleViolation() error = %v for %s", err, namespace)
		}
	}

	if len(fake.createReqs) != 0 {
		t.Fatalf("non-tenant namespace was submitted for ban: %+v", fake.createReqs)
	}
}

func TestHandleViolationAlwaysProtectsSystemNamespaces(t *testing.T) {
	fake := &fakeBanService{}
	svc := NewService(policyRepo(`{
		"enabled": true,
		"dryRun": false,
		"sources": { "procscan": { "enabled": true } },
		"namespaceAllowlist": ["kube-system"]
	}`), fake)

	if err := svc.HandleViolation(context.Background(), Violation{
		Namespace: "kube-system",
		Source:    SourceProcscan,
		IsIllegal: true,
	}); err != nil {
		t.Fatalf("HandleViolation() error = %v", err)
	}
	if len(fake.createReqs) != 0 {
		t.Fatalf("system namespace was submitted for ban: %+v", fake.createReqs)
	}
}

func TestHandleViolationSkipsDryRunPolicy(t *testing.T) {
	fake := &fakeBanService{}
	svc := NewService(policyRepo(`{
		"enabled": true,
		"dryRun": true,
		"sources": {
			"procscan": { "enabled": true }
		},
		"processNameAllowlist": ["xmrig"]
	}`), fake)

	decision, err := svc.HandleViolationDecision(context.Background(), Violation{
		Namespace:    "ns-demo",
		Source:       SourceProcscan,
		ProcessName:  "xmrig",
		DetectorName: "detector",
		IsIllegal:    true,
	})
	if err != nil {
		t.Fatalf("HandleViolationDecision returned error: %v", err)
	}

	if decision.Status != DecisionDryRun || decision.Reason != "policy_dry_run" {
		t.Fatalf("unexpected dry-run decision: %+v", decision)
	}

	if len(fake.statusNamespaces) != 1 {
		t.Fatalf("expected 1 ban status check, got %d", len(fake.statusNamespaces))
	}

	if len(fake.createReqs) != 0 {
		t.Fatalf("expected no ban request, got %d", len(fake.createReqs))
	}
}

func TestHandleViolationSkipsWhenAlreadyBanned(t *testing.T) {
	fake := &fakeBanService{status: &ban.BanStatusResponse{Banned: true}}
	svc := NewService(policyRepo(`{
		"enabled": true,
		"dry_run": false,
		"sources": {
			"procscan": { "enabled": true }
		},
		"processNameAllowlist": ["xmrig"]
	}`), fake)

	err := svc.HandleViolation(context.Background(), Violation{
		Namespace:    "ns-demo",
		Source:       SourceProcscan,
		ProcessName:  "xmrig",
		DetectorName: "detector",
		IsIllegal:    true,
	})
	if err != nil {
		t.Fatalf("HandleViolation returned error: %v", err)
	}

	if len(fake.createReqs) != 0 {
		t.Fatalf("expected no ban request, got %d", len(fake.createReqs))
	}
}

func TestHandleViolationSkipsNonIllegalAndTestEvents(t *testing.T) {
	cases := []struct {
		name      string
		violation Violation
	}{
		{
			name: "non-illegal procscan event",
			violation: Violation{
				Namespace: "demo-ns",
				Source:    SourceProcscan,
				IsIllegal: false,
			},
		},
		{
			name: "complik test event",
			violation: Violation{
				Namespace: "demo-ns",
				Source:    SourceComplik,
				IsIllegal: true,
				IsTest:    true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeBanService{}
			repo := policyRepo(`{
				"enabled": true,
				"dryRun": false,
				"sources": {
					"complik": { "enabled": true },
					"procscan": { "enabled": true }
				}
			}`)
			svc := NewService(repo, fake)

			if err := svc.HandleViolation(context.Background(), tc.violation); err != nil {
				t.Fatalf("HandleViolation returned error: %v", err)
			}

			if repo.calls != 0 {
				t.Fatalf("expected no policy load, got %d", repo.calls)
			}

			if len(fake.createReqs) != 0 {
				t.Fatalf("expected no ban request, got %d", len(fake.createReqs))
			}
		})
	}
}

func TestHandleViolationHonorsNamespacePolicy(t *testing.T) {
	fake := &fakeBanService{}
	svc := NewService(policyRepo(`{
		"enabled": true,
		"dryRun": false,
		"sources": {
			"procscan": { "enabled": true }
		},
		"processNameAllowlist": ["xmrig"],
		"namespaceAllowlist": ["ns-allowed"],
		"namespaceDenylist": ["ns-denied"]
	}`), fake)

	for _, namespace := range []string{"ns-denied", "ns-other"} {
		err := svc.HandleViolation(context.Background(), Violation{
			Namespace:   namespace,
			Source:      SourceProcscan,
			ProcessName: "xmrig",
			IsIllegal:   true,
		})
		if err != nil {
			t.Fatalf("HandleViolation returned error for %s: %v", namespace, err)
		}
	}

	err := svc.HandleViolation(context.Background(), Violation{
		Namespace:   "ns-allowed",
		Source:      SourceProcscan,
		ProcessName: "xmrig",
		IsIllegal:   true,
	})
	if err != nil {
		t.Fatalf("HandleViolation returned error: %v", err)
	}

	if len(fake.createReqs) != 1 {
		t.Fatalf("expected 1 ban request, got %d", len(fake.createReqs))
	}

	if fake.createReqs[0].Namespace != "ns-allowed" {
		t.Fatalf("unexpected namespace: %q", fake.createReqs[0].Namespace)
	}
}

func TestHandleViolationReturnsExecutorError(t *testing.T) {
	expectedErr := errors.New("namespace patch failed")
	fake := &fakeBanService{createErr: expectedErr}
	svc := NewService(policyRepo(`{
		"enabled": true,
		"dryRun": false,
		"sources": {
			"procscan": { "enabled": true }
		},
		"processNameAllowlist": ["xmrig"]
	}`), fake)

	err := svc.HandleViolation(context.Background(), Violation{
		Namespace:   "ns-demo",
		Source:      SourceProcscan,
		ProcessName: "xmrig",
		IsIllegal:   true,
	})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected executor error %v, got %v", expectedErr, err)
	}

	if len(fake.createReqs) != 1 {
		t.Fatalf("expected 1 ban request, got %d", len(fake.createReqs))
	}
}

func policyRepo(config string) *fakePolicyRepository {
	return &fakePolicyRepository{
		configs: []projectconfig.ProjectConfig{
			{
				ConfigName:  policyConfigType,
				ConfigType:  policyConfigType,
				ConfigValue: json.RawMessage(config),
			},
		},
	}
}
