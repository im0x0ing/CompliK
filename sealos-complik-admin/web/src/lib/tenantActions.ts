export function banCreatePath(namespace: string, reason?: string) {
  const params = new URLSearchParams({ namespace, create: "1" });
  if (reason?.trim()) {
    params.set("reason", reason.trim());
  }
  return `/bans?${params.toString()}`;
}

export function unbanCreatePath(namespace: string) {
  return `/unbans?${new URLSearchParams({ namespace, create: "1" }).toString()}`;
}
