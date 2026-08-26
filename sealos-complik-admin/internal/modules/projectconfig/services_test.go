package projectconfig

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestProtectedProcscanConfigsCannotUseGenericWriteAPI(t *testing.T) {
	service := NewService(nil)

	for _, name := range []string{"procscan_rules", "procscan_rules_v2"} {
		t.Run(name, func(t *testing.T) {
			createErr := service.CreateProjectConfig(context.Background(), CreateProjectConfigRequest{
				ConfigName: name, ConfigType: name, ConfigValue: json.RawMessage(`{}`),
			})
			if !errors.Is(createErr, ErrProjectConfigProtected) {
				t.Fatalf("CreateProjectConfig() error = %v", createErr)
			}
			updateErr := service.UpdateProjectConfig(context.Background(), name, UpdateProjectConfigRequest{
				ConfigName: name, ConfigType: name, ConfigValue: json.RawMessage(`{}`),
			})
			if !errors.Is(updateErr, ErrProjectConfigProtected) {
				t.Fatalf("UpdateProjectConfig() error = %v", updateErr)
			}
			deleteErr := service.DeleteProjectConfig(context.Background(), name)
			if !errors.Is(deleteErr, ErrProjectConfigProtected) {
				t.Fatalf("DeleteProjectConfig() error = %v", deleteErr)
			}
		})
	}
}
