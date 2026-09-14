package ban

import (
	"time"

	"sealos-complik-admin/internal/modules/pagequery"
)

type BanNamespaceRequest struct {
	Namespace string `uri:"namespace" binding:"required,max=255"`
}

type BanIDRequest struct {
	ID uint64 `uri:"id" binding:"required,min=1"`
}

type BanScreenshotQueryRequest struct {
	URL string `form:"url" binding:"required,max=2048"`
}

type ListBansQueryRequest struct {
	Page         int    `form:"page"`
	Keyword      string `form:"keyword"`
	OperatorName string `form:"operator_name"`
}

type CreateBanRequest struct {
	Namespace      string     `json:"namespace"       binding:"required,max=255"`
	Reason         string     `json:"reason"          binding:"omitempty,max=10000"`
	ScreenshotURLs []string   `json:"screenshot_urls"`
	BanStartTime   time.Time  `json:"ban_start_time"  binding:"required"`
	BanEndTime     *time.Time `json:"ban_end_time"`
	OperatorName   string     `json:"operator_name"   binding:"required,max=100"`
}

type UploadBanRequest struct {
	Namespace    string `form:"namespace"      binding:"required,max=255"`
	Reason       string `form:"reason"         binding:"omitempty,max=10000"`
	BanStartTime string `form:"ban_start_time" binding:"required"`
	OperatorName string `form:"operator_name"  binding:"required,max=100"`
}

type BanResponse struct {
	ID             uint64     `json:"id"`
	Namespace      string     `json:"namespace"`
	Reason         string     `json:"reason,omitempty"`
	ScreenshotURLs []string   `json:"screenshot_urls,omitempty"`
	BanStartTime   time.Time  `json:"ban_start_time"`
	BanEndTime     *time.Time `json:"ban_end_time,omitempty"`
	OperatorName   string     `json:"operator_name"`
	LabelActionStatus string  `json:"label_action_status,omitempty"`
	LabelActionResult string  `json:"label_action_result,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type BanStatusResponse struct {
	Banned bool `json:"banned"`
}

type PaginatedBanResponse = pagequery.PaginatedResponse[BanResponse]
