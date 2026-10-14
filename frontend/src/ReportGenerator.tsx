import { useEffect, useState } from "react";
import { mutate, request } from "./api";
import type { AppState } from "./types";

type ReportFile = { format: string; bytes: number };
type Report = {
  id: string;
  title: string;
  created_at: string;
  source: "loaded" | "api";
  source_label: string;
  formats: string[];
  filters: { severity: string; status: string; product: string };
  status: string;
  warnings?: string[];
  files: ReportFile[];
};
type ReportJob = {
  id: string;
  running: boolean;
  stage: string;
  message: string;
  warnings?: string[];
  log: string[];
};
type Overview = {
  available: boolean;
  tool: string | null;
  job: ReportJob | null;
  reports: Report[];
  canUseApi: boolean;
  loadedRows: number;
};

const FORMATS: [string, string][] = [
  ["pdf", "PDF"],
  ["html", "HTML"],
  ["csv", "CSV"],
  ["json", "JSON"],
];
const PERIODS: [string, string][] = [
  ["all", "All history"],
  ["7d", "Last 7 days"],
  ["14d", "Last 14 days"],
  ["30d", "Last 30 days"],
  ["90d", "Last 90 days"],
  ["180d", "Last 6 months"],
  ["365d", "Last 365 days"],
  ["2y", "Last 2 years"],
  ["from", "From a date onwards…"],
  ["range", "Custom date range…"],
];
const today = () => new Date().toISOString().slice(0, 10);
const SEVERITIES = ["critical", "high", "medium", "low"];
const STATUSES = ["open", "resolved", "ignored"];
const PRODUCTS: [string, string][] = [
  ["sca", "Open Source (SCA)"],
  ["sast", "Code (SAST)"],
  ["container", "Container"],
  ["iac", "IaC"],
  ["secrets", "Secrets"],
];
const size = (bytes: number) =>
  bytes > 1048576
    ? `${(bytes / 1048576).toFixed(1)} MB`
    : `${Math.max(1, Math.round(bytes / 1024))} KB`;
const cap = (v: string) => v[0].toUpperCase() + v.slice(1);

function Chips({
  values,
  selected,
  onChange,
  label = (v: string) => cap(v),
}: {
  values: string[];
  selected: string[];
  onChange: (next: string[]) => void;
  label?: (v: string) => string;
}) {
  return (
    <div className="chip-row">
      {values.map((v) => (
        <label key={v} className={"chip" + (selected.includes(v) ? " on" : "")}>
          <input
            type="checkbox"
            checked={selected.includes(v)}
            onChange={() =>
              onChange(
                selected.includes(v)
                  ? selected.filter((x) => x !== v)
                  : [...selected, v],
              )
            }
          />
          {label(v)}
        </label>
      ))}
    </div>
  );
}

export function ReportGenerator({
  state,
  workspaceName,
  onNotice,
  onError,
}: {
  state: AppState;
  workspaceName: string;
  onNotice: (m: string) => void;
  onError: (m: string) => void;
}) {
  const [overview, setOverview] = useState<Overview | null>(null),
    [revision, setRevision] = useState(0),
    [busy, setBusy] = useState(false),
    [source, setSource] = useState<"loaded" | "api">("loaded"),
    [formats, setFormats] = useState(["pdf", "html"]),
    [severity, setSeverity] = useState<string[]>([]),
    [status, setStatus] = useState(["open"]),
    [product, setProduct] = useState<string[]>([]),
    // Period: a preset, "from" (start date onwards) or "range" (start + end).
    [period, setPeriod] = useState("all"),
    [fromDate, setFromDate] = useState(""),
    [toDate, setToDate] = useState(today()),
    [title, setTitle] = useState("Snyk vulnerability report"),
    [subtitle, setSubtitle] = useState(""),
    [preparedFor, setPreparedFor] = useState(workspaceName),
    [preparedBy, setPreparedBy] = useState(""),
    [classification, setClassification] = useState("Confidential"),
    [top, setTop] = useState("25"),
    [maxDetailRows, setMaxDetailRows] = useState("500");
  const running = !!overview?.job?.running;
  useEffect(() => {
    const controller = new AbortController();
    request<Overview>("/api/reports/generated", { signal: controller.signal })
      .then(setOverview)
      .catch((e) => {
        if (e.name !== "AbortError") onError(e.message);
      });
    return () => controller.abort();
  }, [revision, state.version]);
  // Poll while a report runs, then refresh the history once it finishes.
  useEffect(() => {
    if (!running) return;
    const id = setInterval(() => setRevision((r) => r + 1), 1500);
    return () => clearInterval(id);
  }, [running]);
  useEffect(() => {
    const job = overview?.job;
    if (job && !job.running && job.stage === "complete") onNotice(job.message);
  }, [overview?.job?.stage]);
  if (!overview) return <p className="muted">Loading report generator…</p>;
  if (!overview.available)
    return (
      <div className="panel">
        <h2>Report generator not found</h2>
        <p className="muted">
          Pulse's bundled copy, <code>vendor/snyk-auto-report.mjs</code>, is
          missing. Reinstall Pulse or run <code>npm run vendor:report</code>, or
          start Pulse with{" "}
          <code>--report-tool /path/to/snyk-auto-report.mjs</code> or set{" "}
          <code>PULSE_REPORT_TOOL</code>.
        </p>
      </div>
    );
  const generate = async () => {
    if (!formats.length) return onError("Choose at least one format.");
    if ((period === "from" || period === "range") && !fromDate)
      return onError("Choose a start date for the period.");
    if (period === "range" && !toDate)
      return onError("Choose an end date for the period.");
    setBusy(true);
    try {
      await mutate("/api/reports/generate", {
        source,
        formats,
        severity: severity.length ? severity : "all",
        status: status.length ? status : "all",
        product: product.length ? product : "all",
        since: period === "from" || period === "range" ? fromDate : period,
        until: period === "range" ? toDate : "",
        title,
        subtitle,
        preparedFor,
        preparedBy,
        classification,
        top,
        maxDetailRows,
      });
      onNotice("Generating report… you can keep using the dashboard.");
      setRevision((r) => r + 1);
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const job = overview.job;
  return (
    <>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Generate a full report</h2>
            <p>
              A complete, shareable vulnerability report — cover, executive
              summary, findings register and per-finding details — produced by
              the Snyk report generator.
            </p>
          </div>
        </div>
        <div className="report-form">
          <div className="report-column">
            <fieldset>
              <legend>1 · Data</legend>
              <div className="source-options">
                <label
                  className={
                    "source-option" + (source === "loaded" ? " on" : "")
                  }
                >
                  <input
                    type="radio"
                    checked={source === "loaded"}
                    onChange={() => setSource("loaded")}
                  />
                  <b>Loaded data</b>
                  <small>
                    {overview.loadedRows
                      ? `${overview.loadedRows.toLocaleString()} issues currently in Pulse (${state.snapshot?.source || "CSV"}). Instant; no Snyk API call.`
                      : "Load a CSV or pull from the Snyk API first."}
                  </small>
                </label>
                <label
                  className={
                    "source-option" +
                    (source === "api" ? " on" : "") +
                    (overview.canUseApi ? "" : " disabled")
                  }
                >
                  <input
                    type="radio"
                    disabled={!overview.canUseApi}
                    checked={source === "api"}
                    onChange={() => setSource("api")}
                  />
                  <b>Live from Snyk</b>
                  <small>
                    {overview.canUseApi
                      ? `Fresh Export API pull for ${state.store?.source?.kind === "api" ? state.store.source.scopeName || "the saved scope" : "the saved scope"}. Takes minutes; uses 1 of 20 exports/hour.`
                      : "Available after pulling data from the Snyk API (token and scope are reused)."}
                  </small>
                </label>
              </div>
              <div className="period-picker">
                <label>
                  Findings first introduced
                  <select
                    aria-label="Report period"
                    value={period}
                    onChange={(e) => setPeriod(e.target.value)}
                  >
                    {PERIODS.map(([value, label]) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
                {(period === "from" || period === "range") && (
                  <label>
                    From
                    <input
                      type="date"
                      aria-label="Period start date"
                      value={fromDate}
                      max={period === "range" && toDate ? toDate : today()}
                      onChange={(e) => setFromDate(e.target.value)}
                    />
                  </label>
                )}
                {period === "range" && (
                  <label>
                    To
                    <input
                      type="date"
                      aria-label="Period end date"
                      value={toDate}
                      min={fromDate || undefined}
                      max={today()}
                      onChange={(e) => setToDate(e.target.value)}
                    />
                  </label>
                )}
              </div>
              <small className="muted">
                {source === "api"
                  ? "Sent to the Snyk Export API as the introduced-date filter."
                  : "Keeps loaded findings whose FIRST_INTRODUCED date falls in this period."}
              </small>
            </fieldset>
            <fieldset>
              <legend>3 · Cover page</legend>
              <div className="form-row">
                <label>
                  Title
                  <input
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                  />
                </label>
                <label>
                  Subtitle
                  <input
                    value={subtitle}
                    onChange={(e) => setSubtitle(e.target.value)}
                    placeholder="Optional"
                  />
                </label>
              </div>
              <div className="form-row">
                <label>
                  Prepared for
                  <input
                    value={preparedFor}
                    onChange={(e) => setPreparedFor(e.target.value)}
                  />
                </label>
                <label>
                  Prepared by
                  <input
                    value={preparedBy}
                    onChange={(e) => setPreparedBy(e.target.value)}
                    placeholder="Optional"
                  />
                </label>
                <label>
                  Classification
                  <input
                    value={classification}
                    onChange={(e) => setClassification(e.target.value)}
                  />
                </label>
              </div>
            </fieldset>
          </div>
          <div className="report-column">
            <fieldset>
              <legend>2 · What to include</legend>
              <span className="field-label">
                Severity <small>(none selected = all)</small>
              </span>
              <Chips
                values={SEVERITIES}
                selected={severity}
                onChange={setSeverity}
              />
              <span className="field-label">
                Status <small>(none selected = all)</small>
              </span>
              <Chips values={STATUSES} selected={status} onChange={setStatus} />
              <span className="field-label">
                Product <small>(none selected = all)</small>
              </span>
              <Chips
                values={PRODUCTS.map(([v]) => v)}
                selected={product}
                onChange={setProduct}
                label={(v) => PRODUCTS.find(([k]) => k === v)?.[1] || v}
              />
              <div className="form-row">
                <label>
                  Detailed findings (top N)
                  <input
                    value={top}
                    onChange={(e) => setTop(e.target.value)}
                    placeholder="25 or all"
                  />
                </label>
                <label>
                  Max rows in findings register
                  <input
                    value={maxDetailRows}
                    onChange={(e) => setMaxDetailRows(e.target.value)}
                    placeholder="500"
                  />
                </label>
              </div>
            </fieldset>
            <fieldset>
              <legend>4 · Formats</legend>
              <Chips
                values={FORMATS.map(([v]) => v)}
                selected={formats}
                onChange={setFormats}
                label={(v) => FORMATS.find(([k]) => k === v)?.[1] || v}
              />
              <small className="muted">
                PDF uses your installed Chrome, Chromium or Edge. Large reports:
                keep the findings register to a few hundred rows for a
                manageable PDF.
              </small>
            </fieldset>
          </div>
        </div>
        <div className="form-actions">
          <small className="muted">
            Reports are saved locally and listed below.
          </small>
          <button
            className="primary"
            disabled={busy || running || !formats.length}
            onClick={generate}
          >
            {running ? "Generating…" : "Generate report"}
          </button>
        </div>
      </section>
      {job && (job.running || job.stage === "failed") && (
        <div
          className={"alert " + (job.stage === "failed" ? "error" : "")}
          role="status"
        >
          <span>
            {job.running ? "↻ " : ""}
            {job.message}
          </span>
          {job.running && (
            <button
              onClick={() =>
                mutate("/api/reports/generated/cancel")
                  .then(() => setRevision((r) => r + 1))
                  .catch((e) => onError(e.message))
              }
            >
              Cancel
            </button>
          )}
        </div>
      )}
      {job?.running && job.log.length > 0 && (
        <details className="report-log">
          <summary>Generator output</summary>
          <pre>{job.log.slice(-20).join("\n")}</pre>
        </details>
      )}
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>Generated reports</h2>
            <p>
              {overview.reports.length ? "Newest first." : "No reports yet."}
            </p>
          </div>
        </div>
        {overview.reports.length > 0 && (
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Report</th>
                  <th>Data</th>
                  <th>Filters</th>
                  <th>Files</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {overview.reports.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <b>{r.title}</b>
                      <small>{new Date(r.created_at).toLocaleString()}</small>
                      {r.warnings?.map((w) => (
                        <small key={w} className="bad">
                          {w}
                        </small>
                      ))}
                    </td>
                    <td>{r.source_label}</td>
                    <td>
                      <small>Severity: {r.filters.severity}</small>
                      <small>Status: {r.filters.status}</small>
                      <small>Product: {r.filters.product}</small>
                    </td>
                    <td className="report-files">
                      <div>
                        {r.files.map((f) => (
                          <a
                            key={f.format}
                            className="button"
                            href={`/api/reports/generated/${r.id}/${f.format}`}
                            target={f.format === "html" ? "_blank" : undefined}
                            rel="noreferrer"
                            title={
                              f.format === "html"
                                ? "Open in a new tab"
                                : "Download"
                            }
                          >
                            {f.format.toUpperCase()}{" "}
                            <small>{size(f.bytes)}</small>
                          </a>
                        ))}
                      </div>
                    </td>
                    <td>
                      <button
                        aria-label={`Delete report ${r.title}`}
                        onClick={() => {
                          if (
                            !confirm(
                              `Delete "${r.title}" (${new Date(r.created_at).toLocaleString()})?`,
                            )
                          )
                            return;
                          mutate(
                            `/api/reports/generated/${r.id}`,
                            undefined,
                            "DELETE",
                          )
                            .then(() => setRevision((x) => x + 1))
                            .catch((e) => onError(e.message));
                        }}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
