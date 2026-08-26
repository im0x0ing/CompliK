package k8s

import (
	"slices"
	"strings"
)

const TenantNamespacePrefix = "ns-"

// ProtectedNamespaces must never receive block.sealos.io/locked even when prefixed
// with ns-.
var ProtectedNamespaces = []string{
	"kube-system",
	"kube-public",
	"kube-node-lease",
	"sealos",
	"block-system",
}

// AllowsTenantNamespaceLock reports whether a namespace may receive the lock label.
func AllowsTenantNamespaceLock(namespace string) bool {
	trimmed := strings.TrimSpace(namespace)
	if trimmed == "" {
		return false
	}
	if !strings.HasPrefix(trimmed, TenantNamespacePrefix) {
		return false
	}
	return !slices.Contains(ProtectedNamespaces, trimmed)
}
