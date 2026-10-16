import { useEffect, useState } from "react";
import { mutate, request } from "./api";
import type { AppState, SnykConnection, SnykScope } from "./types";

type ReportFile = { format: string; bytes: number };
type Report = {
  id: string;
  title: string;
  created_at: string;
  source: string;
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

type Source = "export" | "issues" | "csv" | "cli";
// The report generator's own four data sources, in the order its wizard offers them.
const SOURCES: [Source, string, string][] = [
  ["export", "Pull a full export from Snyk", "Export API: every field, but lags new scans by about 2 hours."],
  ["issues", "Pull live results from Snyk", "Issues API: includes scans that just finished; no EPSS or KEV."],
  ["csv", "Use data already in Pulse", "Reports-tab CSV or an earlier pull. Instant; no Snyk API call."],
  ["cli", "Scan a local folder", "Snyk CLI: snyk code test + snyk test; shows the code at every data-flow step."],
];
const REGIONS: [string, string][] = [
  ["us", "SNYK-US-01 · app.snyk.io"],
  ["us02", "SNYK-US-02 · app.us.snyk.io"],
  ["eu", "SNYK-EU-01 · app.eu.snyk.io"],
  ["au", "SNYK-AU-01 · app.au.snyk.io"],
  ["gov", "SNYK-GOV-01 · app.snykgov.io"],
];
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
    [source, setSource] = useState<Source>("csv"),
    // Scope for the two Snyk API sources, as the CLI wizard asks for it.
    [region, setRegion] = useState("us"),
    [token, setToken] = useState(""),
    [connection, setConnection] = useState<SnykConnection | null>(null),
    [group, setGroup] = useState(""),
    [groupOrgs, setGroupOrgs] = useState<SnykScope[] | null>(null),
    [org, setOrg] = useState(""),
    [targets, setTargets] = useState<SnykScope[] | null>(null),
    [pickedTargets, setPickedTargets] = useState<string[]>([]),
    [scopeBusy, setScopeBusy] = useState(false),
    // CLI: a folder on this machine, and which scans to run.
    [folder, setFolder] = useState(""),
    [cliScans, setCliScans] = useState(["sast", "sca"]),
    // Optional extras.
    [details, setDetails] = useState(true),
    [dataflow, setDataflow] = useState(true),
    [codePath, setCodePath] = useState(""),
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
  const isApi = source === "export" || source === "issues";
  const post = <T,>(path: string, body: unknown) =>
    request<T>(path, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Pulse-Local": "1" },
      body: JSON.stringify(body),
    });
  const resetScope = () => {
    setConnection(null);
    setGroup("");
    setGroupOrgs(null);
    setOrg("");
    setTargets(null);
    setPickedTargets([]);
  };
  // Token and region -> the groups and organizations this token can see.
  const connect = async () => {
    setScopeBusy(true);
    resetScope();
    try {
      const result = await post<SnykConnection>("/api/connection/validate", { token, region });
      setConnection(result);
      setRegion(result.region);
      setToken("");
      setOrg(result.orgs[0]?.id || "");
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setScopeBusy(false);
    }
  };
  const pickGroup = async (id: string) => {
    setGroup(id);
    setOrg("");
    setTargets(null);
    setPickedTargets([]);
    if (!id) {
      setGroupOrgs(null);
      setOrg(connection?.orgs[0]?.id || "");
      return;
    }
    setScopeBusy(true);
    try {
      const r = await post<{ orgs: SnykScope[] }>("/api/connection/orgs", {
        connectionId: connection?.id,
        group: id,
      });
      setGroupOrgs(r.orgs);
      setOrg(r.orgs[0]?.id || "");
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setScopeBusy(false);
    }
  };
  const pickOrg = (id: string) => {
    setOrg(id);
    setTargets(null);
    setPickedTargets([]);
  };
  const loadTargets = async () => {
    setScopeBusy(true);
    try {
      const r = await post<{ targets: SnykScope[] }>("/api/reports/targets", { org, region });
      setTargets(r.targets);
    } catch (e) {
      onError((e as Error).message);
    } finally {
      setScopeBusy(false);
    }
  };
  const orgChoices = group ? groupOrgs || [] : connection?.orgs || [];
  const scopeName =
    orgChoices.find((o) => o.id === org)?.name ||
    connection?.groups.find((g) => g.id === group)?.name ||
    "";
  const generate = async () => {
    if (!formats.length) return onError("Choose at least one format.");
    if (isApi && !org && !group && !overview.canUseApi)
      return onError("Connect to Snyk and choose an organization first.");
    if (source === "cli" && !folder.trim())
      return onError("Enter the folder to scan.");
    if (source === "cli" && !cliScans.length)
      return onError("Choose at least one scan to run.");
    if ((period === "from" || period === "range") && !fromDate)
      return onError("Choose a start date for the period.");
    if (period === "range" && !toDate)
      return onError("Choose an end date for the period.");
    setBusy(true);
    try {
      await mutate("/api/reports/generate", {
        source,
        // Scope: only the two Snyk API sources use these.
        ...(isApi
          ? {
              region,
              group: org ? "" : group,
              org,
              scopeName,
              targets: pickedTargets,
              token: token || undefined,
            }
          : {}),
        ...(source === "cli" ? { path: folder.trim(), cliScanners: cliScans } : {}),
        ...(source !== "cli" && codePath.trim() ? { codePath: codePath.trim() } : {}),
        details,
        dataflow,
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
              <div className="source-options source-options--four">
                {SOURCES.map(([id, name, hint]) => {
                  const disabled = id === "csv" && !overview.loadedRows;
                  return (
                    <label
                      key={id}
                      className={
                        "source-option" +
                        (source === id ? " on" : "") +
                        (disabled ? " disabled" : "")
                      }
                    >
                      <input
                        type="radio"
                        name="report-source"
                        disabled={disabled}
                        checked={source === id}
                        onChange={() => setSource(id)}
                      />
                      <b>{name}</b>
                      <small>
                        {id === "csv" && overview.loadedRows
                          ? `${overview.loadedRows.toLocaleString()} issues currently in Pulse (${state.snapshot?.source || "CSV"}). Instant; no Snyk API call.`
                          : id === "csv"
                            ? "Load a CSV or pull from the Snyk API first."
                            : hint}
                      </small>
                    </label>
                  );
                })}
              </div>
              {isApi && (
                <div className="scope-picker">
                  <div className="form-row">
                    <label>
                      Snyk region
                      <select
                        aria-label="Snyk region"
                        value={region}
                        disabled={scopeBusy}
                        onChange={(e) => {
                          setRegion(e.target.value);
                          resetScope();
                        }}
                      >
                        {REGIONS.map(([v, l]) => (
                          <option key={v} value={v}>
                            {l}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      API token
                      <input
                        type="password"
                        autoComplete="off"
                        placeholder={
                          overview.canUseApi || connection
                            ? "Saved — leave blank to reuse"
                            : "Paste a Snyk token"
                        }
                        value={token}
                        onChange={(e) => setToken(e.target.value)}
                      />
                    </label>
                  </div>
                  <div className="scope-actions">
                    <button
                      type="button"
                      disabled={scopeBusy || (!token && !overview.canUseApi && !connection)}
                      onClick={connect}
                    >
                      {scopeBusy && !connection
                        ? "Connecting…"
                        : connection
                          ? "Reconnect"
                          : "Connect and list groups"}
                    </button>
                    {connection && (
                      <small className="muted">
                        {connection.identity.name} ·{" "}
                        {connection.groups.length} group(s),{" "}
                        {connection.orgs.length} organization(s)
                      </small>
                    )}
                  </div>
                  {connection && (
                    <>
                      <div className="form-row">
                        <label>
                          Group
                          <select
                            aria-label="Group"
                            value={group}
                            disabled={scopeBusy}
                            onChange={(e) => pickGroup(e.target.value)}
                          >
                            <option value="">All groups I can see</option>
                            {connection.groups.map((g) => (
                              <option key={g.id} value={g.id}>
                                {g.name}
                              </option>
                            ))}
                          </select>
                        </label>
                        <label>
                          Organization
                          <select
                            aria-label="Organization"
                            value={org}
                            disabled={scopeBusy}
                            onChange={(e) => pickOrg(e.target.value)}
                          >
                            {!orgChoices.length && <option value="">No organizations</option>}
                            {orgChoices.map((o) => (
                              <option key={o.id} value={o.id}>
                                {o.name}
                              </option>
                            ))}
                          </select>
                        </label>
                      </div>
                      <div className="target-picker">
                        <div className="scope-actions">
                          <span className="field-label">
                            Targets <small>(none selected = every target)</small>
                          </span>
                          <button
                            type="button"
                            disabled={scopeBusy || !org}
                            onClick={loadTargets}
                          >
                            {targets ? "Reload targets" : "Choose targets…"}
                          </button>
                        </div>
                        {targets &&
                          (targets.length ? (
                            <div className="chip-row target-chips">
                              {targets.map((t) => (
                                <label
                                  key={t.id}
                                  className={"chip" + (pickedTargets.includes(t.name) ? " on" : "")}
                                >
                                  <input
                                    type="checkbox"
                                    checked={pickedTargets.includes(t.name)}
                                    onChange={() =>
                                      setPickedTargets(
                                        pickedTargets.includes(t.name)
                                          ? pickedTargets.filter((x) => x !== t.name)
                                          : [...pickedTargets, t.name],
                                      )
                                    }
                                  />
                                  {t.name}
                                </label>
                              ))}
                            </div>
                          ) : (
                            <small className="muted">This organization has no targets.</small>
                          ))}
                      </div>
                    </>
                  )}
                  {!connection && overview.canUseApi && (
                    <small className="muted">
                      Or leave this and use the saved Snyk connection and scope.
                    </small>
                  )}
                </div>
              )}
              {source === "cli" && (
                <div className="scope-picker">
                  <label>
                    Folder to scan
                    <input
                      value={folder}
                      onChange={(e) => setFolder(e.target.value)}
                      placeholder="/Users/you/projects/my-app"
                      spellCheck={false}
                    />
                  </label>
                  <span className="field-label">Scans to run</span>
                  <Chips
                    values={["sast", "sca"]}
                    selected={cliScans}
                    onChange={setCliScans}
                    label={(v) => (v === "sast" ? "Code (snyk code test)" : "Open Source (snyk test)")}
                  />
                  <small className="muted">
                    Runs on this computer with the Snyk CLI's own login (
                    <code>snyk auth</code>), or the token above if you enter one.
                  </small>
                  <label>
                    Snyk token (optional)
                    <input
                      type="password"
                      autoComplete="off"
                      placeholder="Leave blank to use the CLI login"
                      value={token}
                      onChange={(e) => setToken(e.target.value)}
                    />
                  </label>
                </div>
              )}
              {(isApi || source === "csv") && (
                <label className="code-path">
                  Code folder (optional)
                  <input
                    value={codePath}
                    onChange={(e) => setCodePath(e.target.value)}
                    placeholder="/Users/you/projects/my-app"
                    spellCheck={false}
                  />
                  <small className="muted">
                    A checkout of the scanned repository. Snyk returns positions, not code;
                    this shows the code at each data-flow step.
                  </small>
                </label>
              )}
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
                {source === "export"
                  ? "Sent to the Snyk Export API as the introduced-date filter."
                  : source === "issues"
                    ? "Keeps live findings first introduced in this period."
                    : source === "cli"
                      ? "A local scan reports what it finds now; the period does not apply."
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
              {source !== "csv" && (
                <label className="check-row">
                  <input
                    type="checkbox"
                    checked={details}
                    onChange={(e) => setDetails(e.target.checked)}
                  />
                  Include Snyk's description and remediation advice on each detail page
                </label>
              )}
              {(isApi || source === "cli") && (
                <label className="check-row">
                  <input
                    type="checkbox"
                    checked={dataflow}
                    onChange={(e) => setDataflow(e.target.checked)}
                  />
                  Include the Snyk Code data flow
                </label>
              )}
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
