export async function request<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  const response = await fetch(path, options);
  if (!response.ok) {
    const b = await response.json().catch(() => ({}));
    throw new Error(b.detail || "Request failed. Try again.");
  }
  return response.json();
}
export const mutate = <T>(path: string, body?: unknown, method = "POST") =>
  request<T>(path, {
    method,
    headers: { "Content-Type": "application/json", "X-Pulse-Local": "1" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
export const today = () => new Date().toISOString().slice(0, 10);
export const before = (day: string, n: number) => {
  const d = new Date(day + "T00:00:00Z");
  d.setUTCDate(d.getUTCDate() - n);
  return d.toISOString().slice(0, 10);
};
export const pretty = (v: number | null | undefined) =>
  v == null
    ? "—"
    : new Intl.NumberFormat("en", { maximumFractionDigits: 1 }).format(v);
// Data values such as severities are stored lowercase for filtering; show them capitalized.
export const titleCase = (v: string) => (v ? v[0].toUpperCase() + v.slice(1) : v);
