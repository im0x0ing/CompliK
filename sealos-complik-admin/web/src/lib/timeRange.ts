export type ListTimeRange = "24h" | "7d" | "30d" | "all";

export function timeRangeStartMs(range: ListTimeRange, nowMs = Date.now()) {
  if (range === "all") {
    return 0;
  }

  const day = 24 * 60 * 60 * 1000;
  if (range === "24h") {
    return nowMs - day;
  }
  if (range === "7d") {
    return nowMs - 7 * day;
  }
  return nowMs - 30 * day;
}
