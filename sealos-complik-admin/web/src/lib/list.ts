export function parseListPayload<T>(data: unknown): T[] {
  if (Array.isArray(data)) {
    return data as T[];
  }

  if (data && typeof data === "object") {
    const record = data as Record<string, unknown>;
    if (Array.isArray(record.list)) {
      return record.list as T[];
    }
    if (Array.isArray(record.data)) {
      return record.data as T[];
    }
  }

  return [];
}
