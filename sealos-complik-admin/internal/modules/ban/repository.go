package ban

import (
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"sealos-complik-admin/internal/modules/pagequery"
)

const (
	banStatusActionBan   = "ban"
	banStatusActionUnban = "unban"
)

type Repository struct {
	db *gorm.DB
}

type banStatusAction struct {
	Kind      string
	ID        uint64
	CreatedAt time.Time
}

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// CreateBan creates a new ban record.
func (r *Repository) CreateBan(ctx context.Context, ban *Ban) error {
	return r.db.WithContext(ctx).Create(ban).Error
}

func (r *Repository) UpdateBanLabelAction(
	ctx context.Context,
	id uint64,
	status string,
	result string,
) error {
	return r.db.WithContext(ctx).Model(&Ban{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"label_action_status": status,
			"label_action_result": result,
		}).Error
}

// CreateBanIfAbsent atomically creates a ban when the namespace is not
// currently banned. A persistent lock row makes the check safe even when the
// namespace has no existing ban or unban records.
func (r *Repository) CreateBanIfAbsent(ctx context.Context, ban *Ban, now time.Time) (bool, error) {
	if r == nil || r.db == nil {
		return false, errors.New("ban database is required")
	}

	created := false
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		lock := &BanNamespaceLock{Namespace: ban.Namespace}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "namespace"}},
			DoNothing: true,
		}).Create(lock).Error; err != nil {
			return err
		}

		var locked BanNamespaceLock
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("namespace = ?", ban.Namespace).
			First(&locked).Error; err != nil {
			return err
		}

		active, err := hasActiveBan(tx, ban.Namespace, now)
		if err != nil {
			return err
		}
		if active {
			var current Ban
			action, err := getLatestBanStatusAction(tx, ban.Namespace, now)
			if err != nil {
				return err
			}
			if action.Kind != banStatusActionBan {
				return nil
			}
			if err := tx.Where("id = ?", action.ID).First(&current).Error; err != nil {
				return err
			}
			if current.LabelActionStatus != LabelActionPending &&
				current.LabelActionStatus != LabelActionFailed &&
				current.LabelActionStatus != "" {
				return nil
			}
			*ban = current
			created = true
			return nil
		}

		ban.LabelActionStatus = LabelActionPending
		if err := tx.Create(ban).Error; err != nil {
			return err
		}
		created = true
		return nil
	})

	return created, err
}

// GetBansByNamespace returns all ban records for the given namespace.
func (r *Repository) GetBansByNamespace(ctx context.Context, namespace string) ([]Ban, error) {
	var bans []Ban
	if err := r.db.WithContext(ctx).
		Where("namespace = ?", namespace).
		Order("ban_start_time DESC, id DESC").
		Find(&bans).
		Error; err != nil {
		return nil, err
	}

	if len(bans) == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	return bans, nil
}

// ListBans returns all ban records.
func (r *Repository) ListBans(ctx context.Context) ([]Ban, error) {
	var bans []Ban
	if err := r.db.WithContext(ctx).
		Order("ban_start_time DESC, id DESC").
		Find(&bans).
		Error; err != nil {
		return nil, err
	}

	return bans, nil
}

func (r *Repository) ListBansPage(
	ctx context.Context,
	options pagequery.Options,
	keyword string,
	operatorName string,
) ([]Ban, int64, error) {
	var total int64

	countQuery := r.buildListQuery(ctx, keyword, operatorName)
	if err := countQuery.Model(&Ban{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var bans []Ban

	query := r.buildListQuery(ctx, keyword, operatorName)
	if err := query.
		Order("ban_start_time DESC, id DESC").
		Limit(options.PageSize).
		Offset(options.Offset()).
		Find(&bans).Error; err != nil {
		return nil, 0, err
	}

	return bans, total, nil
}

func (r *Repository) buildListQuery(
	ctx context.Context,
	keyword string,
	operatorName string,
) *gorm.DB {
	query := r.db.WithContext(ctx).Model(&Ban{})
	if strings.TrimSpace(keyword) != "" {
		value := "%" + strings.ToLower(strings.TrimSpace(keyword)) + "%"
		query = query.Where("LOWER(namespace) LIKE ?", value)
	}

	if strings.TrimSpace(operatorName) != "" {
		query = query.Where("operator_name = ?", strings.TrimSpace(operatorName))
	}

	return query
}

// DeleteBanByID deletes a single ban record by id.
func (r *Repository) DeleteBanByID(ctx context.Context, id uint64) error {
	result := r.db.WithContext(ctx).Where("id = ?", id).Delete(&Ban{})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

// HasActiveBan reports whether active ban actions leave the namespace banned.
func (r *Repository) HasActiveBan(
	ctx context.Context,
	namespace string,
	now time.Time,
) (bool, error) {
	return hasActiveBan(r.db.WithContext(ctx), namespace, now)
}

func (r *Repository) ListRetryableLabelBans(
	ctx context.Context,
	now time.Time,
	limit int,
) ([]Ban, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("ban database is required")
	}
	if limit <= 0 {
		limit = 50
	}

	var candidates []Ban
	if err := r.db.WithContext(ctx).
		Where(
			"label_action_status IN ? OR COALESCE(label_action_status, '') = ''",
			[]string{LabelActionPending, LabelActionFailed},
		).
		Order("id ASC").
		Limit(limit * 4).
		Find(&candidates).Error; err != nil {
		return nil, err
	}

	retryable := make([]Ban, 0, limit)
	for i := range candidates {
		ban := candidates[i]
		active, err := hasActiveBan(r.db.WithContext(ctx), ban.Namespace, now)
		if err != nil {
			return nil, err
		}
		if !active {
			continue
		}

		action, err := getLatestBanStatusAction(r.db.WithContext(ctx), ban.Namespace, now)
		if err != nil {
			return nil, err
		}
		if action.Kind != banStatusActionBan || action.ID != ban.ID {
			continue
		}

		retryable = append(retryable, ban)
		if len(retryable) >= limit {
			break
		}
	}

	return retryable, nil
}

func hasActiveBan(db *gorm.DB, namespace string, now time.Time) (bool, error) {
	action, err := getLatestBanStatusAction(db, namespace, now)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}

		return false, err
	}

	return action.Kind == banStatusActionBan, nil
}

func (r *Repository) getLatestBanStatusAction(
	ctx context.Context,
	namespace string,
	now time.Time,
) (*banStatusAction, error) {
	return getLatestBanStatusAction(r.db.WithContext(ctx), namespace, now)
}

func getLatestBanStatusAction(
	db *gorm.DB,
	namespace string,
	now time.Time,
) (*banStatusAction, error) {
	var action banStatusAction
	if err := db.
		Raw(`
SELECT kind, id, created_at
FROM (
		SELECT ? AS kind, id, created_at, 0 AS action_rank
		FROM bans
		WHERE namespace = ?
			AND ban_start_time <= ?
			AND (ban_end_time IS NULL OR ban_end_time > ?)
		UNION ALL
		SELECT ? AS kind, id, created_at, 1 AS action_rank
		FROM unbans
		WHERE namespace = ?
) AS actions
ORDER BY created_at DESC, action_rank DESC, id DESC
LIMIT 1
	`, banStatusActionBan, namespace, now, now, banStatusActionUnban, namespace).
		Scan(&action).Error; err != nil {
		return nil, err
	}

	if action.ID == 0 && action.Kind == "" {
		return nil, gorm.ErrRecordNotFound
	}

	return &action, nil
}
