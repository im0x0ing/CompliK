const TENANT_PREFIX = "ns-";

const PROTECTED_NAMESPACES = new Set([
  "kube-system",
  "kube-public",
  "kube-node-lease",
  "sealos",
  "block-system",
]);

export function isKubernetesNamespace(value: string) {
  return value.length <= 63 && /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(value);
}

export function isLockableTenantNamespace(value: string) {
  const namespace = value.trim();
  return (
    isKubernetesNamespace(namespace) &&
    namespace.startsWith(TENANT_PREFIX) &&
    namespace.length > TENANT_PREFIX.length &&
    !PROTECTED_NAMESPACES.has(namespace)
  );
}

export function tenantNamespaceHint() {
  return "只能封禁租户 Namespace（必须以 ns- 开头）。系统命名空间不会被打上封禁标签。";
}
