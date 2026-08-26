package procscanviolation

import (
	"context"
	"errors"
	"strings"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"gorm.io/gorm"
	"sealos-complik-admin/internal/modules/violationquery"
)

type Repository struct {
	db *gorm.DB
}

const procscanEffectiveViolationCondition = "is_illegal = TRUE"

func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) CreateViolation(ctx context.Context, violation *ProcscanViolationEvent) (bool, error) {
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(violation).Error; err != nil {
			return err
		}

		if !violation.IsIllegal {
			return tx.Model(&ProcscanViolationEvent{}).
				Where("id = ?", violation.ID).
				Update("is_illegal", false).Error
		}

		return nil
	})
	if err == nil {
		return true, nil
	}

	var mysqlErr *mysqlDriver.MySQLError
	if errors.As(err, &mysqlErr) && mysqlErr.Number == 1062 {
		return false, nil
	}

	return false, err
}

func (r *Repository) GetViolationByEventID(
	ctx context.Context,
	eventID string,
) (*ProcscanViolationEvent, error) {
	var violation ProcscanViolationEvent
	if err := r.db.WithContext(ctx).
		Where("event_id = ?", eventID).
		First(&violation).Error; err != nil {
		return nil, err
	}

	return &violation, nil
}

func (r *Repository) UpdateAutobanDecision(
	ctx context.Context,
	id uint64,
	status string,
	reason string,
	attemptCount int,
	nextRetryAt *time.Time,
) error {
	return r.db.WithContext(ctx).Model(&ProcscanViolationEvent{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"autoban_status":        status,
			"autoban_reason":        reason,
			"autoban_attempt_count": attemptCount,
			"autoban_next_retry_at": nextRetryAt,
		}).Error
}

func (r *Repository) GetViolationsByNamespace(
	ctx context.Context,
	namespace string,
	includeAll bool,
) ([]ProcscanViolationEvent, error) {
	var violations []ProcscanViolationEvent

	query := r.db.WithContext(ctx).Where("namespace = ?", namespace)
	if !includeAll {
		query = query.Where(procscanEffectiveViolationCondition)
	}

	if err := query.
		Order("detected_at DESC, id DESC").
		Find(&violations).Error; err != nil {
		return nil, err
	}

	if len(violations) == 0 {
		return nil, gorm.ErrRecordNotFound
	}

	return violations, nil
}

func (r *Repository) ListViolations(
	ctx context.Context,
	includeAll bool,
) ([]ProcscanViolationEvent, error) {
	var violations []ProcscanViolationEvent

	query := r.buildListQuery(ctx, includeAll, violationquery.ListOptions{})

	if err := query.Order("detected_at DESC, id DESC").Find(&violations).Error; err != nil {
		return nil, err
	}

	return violations, nil
}

func (r *Repository) ListViolationsPage(
	ctx context.Context,
	options violationquery.ListOptions,
) ([]ProcscanViolationEvent, int64, error) {
	var total int64

	countQuery := r.buildListQuery(ctx, options.IncludeAll, options)
	if err := countQuery.Model(&ProcscanViolationEvent{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var violations []ProcscanViolationEvent

	query := r.buildListQuery(ctx, options.IncludeAll, options)
	if err := query.
		Order("detected_at DESC, id DESC").
		Limit(options.PageSize).
		Offset(options.Offset()).
		Find(&violations).Error; err != nil {
		return nil, 0, err
	}

	return violations, total, nil
}

func (r *Repository) buildListQuery(
	ctx context.Context,
	includeAll bool,
	options violationquery.ListOptions,
) *gorm.DB {
	query := r.db.WithContext(ctx).Model(&ProcscanViolationEvent{})
	if !includeAll {
		query = query.Where(procscanEffectiveViolationCondition)
	}

	if options.StartTime != nil {
		query = query.Where("detected_at >= ?", *options.StartTime)
	}

	if options.Keyword != "" {
		keyword := "%" + strings.ToLower(options.Keyword) + "%"
		query = query.Where(
			r.db.Where("LOWER(namespace) LIKE ?", keyword).
				Or("LOWER(pod_name) LIKE ?", keyword).
				Or("LOWER(node_name) LIKE ?", keyword).
				Or("LOWER(process_name) LIKE ?", keyword).
				Or("LOWER(process_command) LIKE ?", keyword).
				Or("LOWER(match_rule) LIKE ?", keyword).
				Or("LOWER(message) LIKE ?", keyword),
		)
	}

	return query
}

func (r *Repository) DeleteViolationByID(ctx context.Context, id uint64) error {
	result := r.db.WithContext(ctx).Where("id = ?", id).Delete(&ProcscanViolationEvent{})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}

func (r *Repository) DeleteViolationsByNamespace(ctx context.Context, namespace string) error {
	result := r.db.WithContext(ctx).
		Where("namespace = ?", namespace).
		Delete(&ProcscanViolationEvent{})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}

	return nil
}
