package ban

import (
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
)

const legacyNamespaceColumn = "user" + "_id"

const (
	LabelActionPending = "pending"
	LabelActionApplied = "applied"
	LabelActionFailed  = "failed"
)

type Ban struct {
	// ID remains the internal primary key for joins and stable references.
	ID                uint64     `gorm:"primaryKey;autoIncrement" json:"id"`
	Namespace         string     `gorm:"size:255;not null;index"  json:"namespace"`
	Reason            string     `gorm:"type:text"                json:"reason,omitempty"`
	ScreenshotURLs    StringList `gorm:"type:json"                json:"screenshot_urls,omitempty"`
	BanStartTime      time.Time  `gorm:"not null"                 json:"ban_start_time"`
	BanEndTime        *time.Time `                                json:"ban_end_time,omitempty"`
	OperatorName      string     `gorm:"size:100;not null"        json:"operator_name"`
	LabelActionStatus string     `gorm:"size:32;index"             json:"label_action_status,omitempty"`
	LabelActionResult string     `gorm:"type:text"                 json:"label_action_result,omitempty"`
	CreatedAt         time.Time  `gorm:"autoCreateTime"           json:"created_at"`
	UpdatedAt         time.Time  `gorm:"autoUpdateTime"           json:"updated_at"`
}

// BanNamespaceLock serializes state-changing ban operations for one namespace.
// Rows are intentionally retained so a transaction can lock a namespace even
// when it has no ban history yet.
type BanNamespaceLock struct {
	Namespace string    `gorm:"primaryKey;size:255" json:"namespace"`
	CreatedAt time.Time `gorm:"autoCreateTime"     json:"created_at"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"     json:"updated_at"`
}

func (BanNamespaceLock) TableName() string {
	return "ban_namespace_locks"
}

// AutoMigrate creates or updates the bans table schema.
func AutoMigrate(db *gorm.DB) error {
	if db == nil {
		return errors.New("ban automigrate: database is nil")
	}

	if db.Migrator().HasColumn(&Ban{}, legacyNamespaceColumn) &&
		!db.Migrator().HasColumn(&Ban{}, "namespace") {
		if err := db.Migrator().
			RenameColumn(&Ban{}, legacyNamespaceColumn, "namespace"); err != nil {
			return fmt.Errorf("ban rename legacy namespace column: %w", err)
		}
	}

	if err := db.AutoMigrate(&Ban{}); err != nil {
		return fmt.Errorf("ban automigrate: %w", err)
	}
	if err := db.AutoMigrate(&BanNamespaceLock{}); err != nil {
		return fmt.Errorf("ban namespace lock automigrate: %w", err)
	}

	return nil
}
