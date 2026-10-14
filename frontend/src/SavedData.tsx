import { useEffect, useState } from "react";
import { before, mutate, request, today } from "./api";
import type { AppState, Version } from "./types";

const windows: [string, number | null][] = [
  ["Same range, up to today", null],
  ["Last 7 days", 7],
  ["Last 30 days", 30],
  ["Last 60 days", 60],
  ["Last 90 days", 90],
  ["Last 6 months", 182],
  ["Last 12 months", 365],
];

/** Start a refresh of the saved API scope; prompts for a token only when needed. */
export async function startRefresh(from: string | null, token?: string) {
  const response = await fetch("/api/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Pulse-Local": "1" },
    body: JSON.stringify({
      ...(from ? { from } : {}),
      ...(token ? { token } : {}),
    }),
  });
  const body = await response.json().catch(() => ({}));
  if (response.ok) return { started: true, needsToken: false, detail: "" };
  return {
    started: false,
    needsToken: !!body.needsToken,
    detail: String(body.detail || "Refresh failed. Try again."),
  };
}

export function SavedData({
  state,
  onChanged,
  onError,
}: {
  state: AppState;
  onChanged: (message: string) => void;
  onError: (message: string) => void;
}) {
  const [versions, setVersions] = useState<Version[]>([]),
    [days, setDays] = useState<string>(""),
    [custom, setCustom] = useState(""),
    [token, setToken] = useState(""),
    [askToken, setAskToken] = useState(false),
    [busy, setBusy] = useState(false);
  const source = state.store?.source;
  const running = !!state.job?.running;
  useEffect(() => {
    if (!state.store?.enabled) return;
    const controller = new AbortController();
    request<Version[]>("/api/versions", { signal: controller.signal })
      .then(setVersions)
      .catch((e) => {
        if (e.name !== "AbortError") onError(e.message);
      });
    return () => controller.abort();
  }, [state.version, state.job?.stage, state.store?.enabled]);
  if (!state.store?.enabled)
    return (
      <p className="muted">
        Saved data is off for this session (started with --no-store).
      </p>
    );
  const from = custom || (days ? before(today(), Number(days) - 1) : null);
  const refresh = async () => {
    setBusy(true);
    try {
      const result = await startRefresh(from, token.trim() || undefined);
      if (result.started) {
        setToken("");
        setAskToken(false);
        onChanged("Refreshing from Snyk. A new version is saved when the pull completes.");
      } else {
        setAskToken(result.needsToken);
        onError(result.detail);
      }
    } finally {
      setBusy(false);
    }
  };
  const act = async (fn: () => Promise<unknown>, message: string) => {
    setBusy(true);
    try {
      await fn();
      onChanged(message);
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const describe = (v: Version) =>
    v.from && v.from > "1970-01-02"
      ? `${v.from.slice(0, 10)} → ${v.as_of}`
      : `All history → ${v.as_of}`;
  return (
    <>
      <div className="saved-source">
        {source?.kind === "api" ? (
          <>
            <div>
              <b>Snyk API · {source.scopeName || source.org || source.group}</b>
              <small>
                {source.group ? "Group" : "Organization"} · region {source.region} ·{" "}
                {source.datasets.join(", ")} · last pulled{" "}
                {new Date(source.pulledAt).toLocaleString()}
                {state.store.tokenSaved ? " · token saved" : " · token not saved"}
              </small>
            </div>
            <div className="refresh-controls">
              <label>
                Refresh range
                <select
                  aria-label="Refresh range"
                  value={days}
                  disabled={busy || running}
                  onChange={(e) => {
                    setDays(e.target.value);
                    setCustom("");
                  }}
                >
                  {windows.map(([label, n]) => (
                    <option key={label} value={n ?? ""}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                Or from
                <input
                  aria-label="Refresh from date"
                  type="date"
                  max={today()}
                  value={custom}
                  disabled={busy || running}
                  onChange={(e) => setCustom(e.target.value)}
                />
              </label>
              {askToken && (
                <label>
                  Snyk token
                  <input
                    aria-label="Snyk token for refresh"
                    type="password"
                    autoComplete="off"
                    value={token}
                    onChange={(e) => setToken(e.target.value)}
                  />
                </label>
              )}
              <button
                className="primary"
                disabled={busy || running || (askToken && !token.trim())}
                onClick={refresh}
              >
                ↻ Refresh to today
              </button>
            </div>
            <small className="muted">
              Pulls the full range again{" "}
              {from
                ? `from ${from}`
                : source.from > "1970-01-02"
                  ? `from ${source.from.slice(0, 10)}`
                  : "across all history"}{" "}
              up to today and saves it as a new version. Earlier versions are kept.
            </small>
          </>
        ) : source?.kind === "csv" ? (
          <div>
            <b>CSV · {source.fileName || source.dataset}</b>
            <small>
              Data as of {source.asOf} · imported{" "}
              {new Date(source.importedAt).toLocaleString()}. Import a newer CSV with
              Add data to save a new version.
            </small>
          </div>
        ) : (
          <p className="muted">
            Nothing saved yet. Your next CSV import or API pull is saved automatically.
          </p>
        )}
      </div>
      {state.store.warning && <p className="alert error">{state.store.warning}</p>}
      {versions.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Version</th>
                <th>Saved</th>
                <th>Source</th>
                <th>Data range</th>
                <th>Issues</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {versions.map((v) => {
                const current = v.id === state.version;
                return (
                  <tr key={v.id}>
                    <td>
                      v{v.id}
                      {current && <small>Open now</small>}
                    </td>
                    <td>{new Date(v.created_at).toLocaleString()}</td>
                    <td>{v.source}</td>
                    <td>{describe(v)}</td>
                    <td>{v.issues.toLocaleString()}</td>
                    <td className="version-actions">
                      <button
                        disabled={busy || running || current}
                        onClick={() =>
                          act(
                            () => mutate("/api/versions/restore", { id: v.id }),
                            `Opened version ${v.id}.`,
                          )
                        }
                      >
                        Open
                      </button>
                      <button
                        disabled={busy || current}
                        aria-label={`Delete version ${v.id}`}
                        onClick={() => {
                          if (confirm(`Delete saved version ${v.id}? This cannot be undone.`))
                            void act(
                              () => mutate(`/api/versions/${v.id}`, undefined, "DELETE"),
                              `Deleted version ${v.id}.`,
                            );
                        }}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <small className="muted">
        Stored in {state.store.location} (owner-only). The last 10 versions are kept.
        Run <code>node pulse.mjs --forget</code> to delete saved data and the token.
      </small>
    </>
  );
}
