package k8s

import "testing"

func TestAllowsTenantNamespaceLock(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		want      bool
	}{
		{name: "tenant namespace", namespace: "ns-demo", want: true},
		{name: "trimmed tenant namespace", namespace: "  ns-demo  ", want: true},
		{name: "system default", namespace: "default", want: false},
		{name: "ingress", namespace: "ingress-nginx", want: false},
		{name: "wrong prefix", namespace: "demo-ns", want: false},
		{name: "protected kube-system", namespace: "kube-system", want: false},
		{name: "empty", namespace: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AllowsTenantNamespaceLock(tt.namespace); got != tt.want {
				t.Fatalf("AllowsTenantNamespaceLock(%q) = %v, want %v", tt.namespace, got, tt.want)
			}
		})
	}
}
