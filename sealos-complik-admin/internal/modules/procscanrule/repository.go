package procscanrule

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"sealos-complik-admin/internal/modules/projectconfig"
)

type DatabaseRepository struct {
	db *gorm.DB
}

func NewRepository(db *gorm.DB) *DatabaseRepository {
	return &DatabaseRepository{db: db}
}

func (r *DatabaseRepository) GetProjectConfigByName(
	ctx context.Context,
	name string,
) (*projectconfig.ProjectConfig, error) {
	var config projectconfig.ProjectConfig
	err := r.db.WithContext(ctx).Where("config_name = ?", name).First(&config).Error
	return &config, err
}

func (r *DatabaseRepository) CreateProjectConfig(
	ctx context.Context,
	config *projectconfig.ProjectConfig,
) error {
	return r.db.WithContext(ctx).Create(config).Error
}

func (r *DatabaseRepository) UpdateProjectConfig(
	ctx context.Context,
	config *projectconfig.ProjectConfig,
) error {
	return r.db.WithContext(ctx).Save(config).Error
}

func (r *DatabaseRepository) ListProjectConfigsByType(
	ctx context.Context,
	configType string,
) ([]projectconfig.ProjectConfig, error) {
	configs := make([]projectconfig.ProjectConfig, 0)
	err := r.db.WithContext(ctx).
		Where("config_type = ?", configType).
		Order("id ASC").
		Find(&configs).Error
	return configs, err
}

func (r *DatabaseRepository) UpdateRuleSetAtomically(
	ctx context.Context,
	expectedRevision uint64,
	next RuleSet,
	legacy LegacyRuleSet,
) error {
	if r == nil || r.db == nil {
		return errors.New("procscan rule database is required")
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current projectconfig.ProjectConfig
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("config_name = ?", V2ConfigName).
			First(&current).Error; err != nil {
			return err
		}

		var currentRules RuleSet
		if err := json.Unmarshal(current.ConfigValue, &currentRules); err != nil {
			return fmt.Errorf("decode current procscan V2 rules: %w", err)
		}
		if currentRules.RulesetRevision != expectedRevision {
			return ErrRevisionConflict
		}

		nextJSON, err := json.Marshal(next)
		if err != nil {
			return fmt.Errorf("encode procscan V2 rules: %w", err)
		}
		if err := tx.Model(&projectconfig.ProjectConfig{}).
			Where("id = ?", current.ID).
			Updates(map[string]any{
				"config_type":  V2ConfigType,
				"config_value": nextJSON,
			}).Error; err != nil {
			return err
		}

		legacyJSON, err := json.Marshal(legacy)
		if err != nil {
			return fmt.Errorf("encode procscan V1 projection: %w", err)
		}
		legacyConfig := projectconfig.ProjectConfig{
			ConfigName:  LegacyConfigName,
			ConfigType:  LegacyConfigType,
			ConfigValue: legacyJSON,
			Description: "Procscan V1 compatibility projection",
		}
		return tx.Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "config_name"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"config_type", "config_value", "description", "updated_at",
			}),
		}).Create(&legacyConfig).Error
	})
}
