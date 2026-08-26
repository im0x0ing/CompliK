//nolint:testpackage // Tests set unexported service clock and inspect unexported model fields.
package ban

import (
	"context"
	"errors"
	"testing"
	"time"

	"sealos-complik-admin/internal/modules/pagequery"
)

type fakeBanRepository struct {
	created    []*Ban
	deletedIDs []uint64
}

func (f *fakeBanRepository) CreateBan(ctx context.Context, ban *Ban) error {
	f.created = append(f.created, ban)
	ban.ID = uint64(len(f.created))
	return nil
}

func (f *fakeBanRepository) DeleteBanByID(ctx context.Context, id uint64) error {
	f.deletedIDs = append(f.deletedIDs, id)

	filtered := f.created[:0]
	for _, ban := range f.created {
		if ban.ID == id {
			continue
		}

		filtered = append(filtered, ban)
	}

	f.created = filtered

	return nil
}

func (f *fakeBanRepository) UpdateBanLabelAction(
	_ context.Context,
	id uint64,
	status string,
	result string,
) error {
	for _, ban := range f.created {
		if ban.ID == id {
			ban.LabelActionStatus = status
			ban.LabelActionResult = result
			return nil
		}
	}
	return nil
}

func (f *fakeBanRepository) GetBansByNamespace(context.Context, string) ([]Ban, error) {
	return nil, nil
}

func (f *fakeBanRepository) ListBans(context.Context) ([]Ban, error) {
	return nil, nil
}

func (f *fakeBanRepository) ListBansPage(
	context.Context,
	pagequery.Options,
	string,
	string,
) ([]Ban, int64, error) {
	return nil, 0, nil
}

func (f *fakeBanRepository) HasActiveBan(context.Context, string, time.Time) (bool, error) {
	return false, nil
}

func (f *fakeBanRepository) ListRetryableLabelBans(
	_ context.Context,
	_ time.Time,
	limit int,
) ([]Ban, error) {
	retryable := make([]Ban, 0)
	for _, ban := range f.created {
		if ban.LabelActionStatus != LabelActionPending &&
			ban.LabelActionStatus != LabelActionFailed &&
			ban.LabelActionStatus != "" {
			continue
		}
		retryable = append(retryable, *ban)
		if limit > 0 && len(retryable) >= limit {
			break
		}
	}

	return retryable, nil
}

type failingNamespaceLocker struct {
	called bool
}

func (l *failingNamespaceLocker) EnsureLocked(context.Context, string) (bool, error) {
	l.called = true
	return false, errors.New("label patch failed")
}

func (l *failingNamespaceLocker) EnsureUnlocked(context.Context, string) (bool, error) {
	return false, nil
}

type recordingNamespaceLocker struct {
	locked []string
}

func (l *recordingNamespaceLocker) EnsureLocked(_ context.Context, namespace string) (bool, error) {
	l.locked = append(l.locked, namespace)
	return true, nil
}

func (l *recordingNamespaceLocker) EnsureUnlocked(context.Context, string) (bool, error) {
	return false, nil
}

func TestReconcilePendingLabelsRetriesFailedBans(t *testing.T) {
	repo := &fakeBanRepository{
		created: []*Ban{{
			ID:                7,
			Namespace:         "ns-demo",
			LabelActionStatus: LabelActionFailed,
		}},
	}
	locker := &recordingNamespaceLocker{}
	svc := NewService(repo, nil, "", locker)
	svc.now = func() time.Time { return time.Date(2026, time.August, 21, 8, 0, 0, 0, time.UTC) }

	if err := svc.ReconcilePendingLabels(context.Background(), 10); err != nil {
		t.Fatalf("ReconcilePendingLabels() error = %v", err)
	}

	if len(locker.locked) != 1 || locker.locked[0] != "ns-demo" {
		t.Fatalf("locked namespaces = %v, want [ns-demo]", locker.locked)
	}
	if repo.created[0].LabelActionStatus != LabelActionApplied {
		t.Fatalf("label action status = %q, want %q", repo.created[0].LabelActionStatus, LabelActionApplied)
	}
}

func TestReconcilePendingLabelsSkipsAppliedBans(t *testing.T) {
	repo := &fakeBanRepository{
		created: []*Ban{{
			ID:                8,
			Namespace:         "ns-demo",
			LabelActionStatus: LabelActionApplied,
		}},
	}
	locker := &recordingNamespaceLocker{}
	svc := NewService(repo, nil, "", locker)

	if err := svc.ReconcilePendingLabels(context.Background(), 10); err != nil {
		t.Fatalf("ReconcilePendingLabels() error = %v", err)
	}
	if len(locker.locked) != 0 {
		t.Fatalf("locked namespaces = %v, want none", locker.locked)
	}
}

func TestReconcilePendingLabelsFailsClosedWithoutLocker(t *testing.T) {
	svc := NewService(&fakeBanRepository{}, nil, "", nil)
	if err := svc.ReconcilePendingLabels(context.Background(), 10); !errors.Is(err, ErrNamespaceLockerUnavailable) {
		t.Fatalf("ReconcilePendingLabels() error = %v, want locker error", err)
	}
}

func TestCreateBanPreservesRecordWhenLabelFails(t *testing.T) {
	repo := &fakeBanRepository{}
	locker := &failingNamespaceLocker{}
	svc := NewService(repo, nil, "", locker)
	svc.now = func() time.Time { return time.Date(2026, time.July, 29, 8, 0, 0, 0, time.UTC) }

	err := svc.CreateBan(context.Background(), CreateBanRequest{
		Namespace:    "demo-ns",
		Reason:       "manual ban",
		BanStartTime: svc.now(),
		OperatorName: "admin",
	})
	if err == nil {
		t.Fatal("expected label failure")
	}

	if !locker.called {
		t.Fatal("expected namespace locker to be called")
	}

	if len(repo.created) != 1 {
		t.Fatalf("expected failed ban record to be preserved, got %d", len(repo.created))
	}

	if repo.created[0].LabelActionStatus != LabelActionFailed {
		t.Fatalf("label action status = %q, want %q", repo.created[0].LabelActionStatus, LabelActionFailed)
	}
	if len(repo.deletedIDs) != 0 {
		t.Fatalf("expected no rollback delete, got %d", len(repo.deletedIDs))
	}
}

func TestCreateBanFailsClosedWithoutNamespaceLocker(t *testing.T) {
	repo := &fakeBanRepository{}
	svc := NewService(repo, nil, "", nil)

	err := svc.CreateBan(context.Background(), CreateBanRequest{
		Namespace:    "demo-ns",
		Reason:       "manual ban",
		BanStartTime: time.Now(),
		OperatorName: "admin",
	})
	if !errors.Is(err, ErrNamespaceLockerUnavailable) {
		t.Fatalf("CreateBan() error = %v, want namespace locker error", err)
	}
	if len(repo.created) != 0 {
		t.Fatalf("expected no ban record without locker, got %d", len(repo.created))
	}
}
