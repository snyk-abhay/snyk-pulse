import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import {
  mkdir,
  readdir,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { encodeCSV } from "./csv.mjs";

// Pulse ships its own copy of the snyk_report generator (vendor/, refreshed
// with `npm run vendor:report`). It has no programmatic API (importing it runs
// it), so Pulse runs it as a child process and reads the files it writes.
const BUNDLED = fileURLToPath(
  new URL("../vendor/snyk-auto-report.mjs", import.meta.url),
);
export const FORMATS = ["pdf", "html", "csv", "json"];
const SEVERITIES = ["critical", "high", "medium", "low"];
const STATUSES = ["open", "resolved", "ignored"];
const PRODUCTS = ["sca", "sast", "container", "iac", "secrets"];
const SINCE = ["7d", "14d", "30d", "90d", "180d", "365d", "2y", "all"];
const DAY = /^\d{4}-\d{2}-\d{2}$/;
const realDay = (v) => DAY.test(v) && new Date(`${v}T00:00:00Z`).toISOString().slice(0, 10) === v;
const MIME = {
  pdf: "application/pdf",
  html: "text/html; charset=utf-8",
  csv: "text/csv; charset=utf-8",
  json: "application/json; charset=utf-8",
};
const ID = /^[0-9]{8}-[0-9]{6}-[a-z0-9]{4}$/;
// The report generator's four data sources, as its own wizard offers them.
//   export  Export API: every field, lags new scans by about 2 hours
//   issues  Issues API: live, includes scans that just finished; no EPSS or KEV
//   csv     a Snyk CSV: the data already loaded in Pulse
//   cli     the Snyk CLI scanning a local folder; code shown at every flow step
// "api" and "loaded" are the names older clients sent; they still work.
export const SOURCES = ["export", "issues", "csv", "cli"];
const SOURCE_ALIAS = { api: "export", loaded: "csv" };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const REGION = /^(us|us01|us02|eu|au|gov)$/;
// Target and project names go to the tool as one comma-separated flag.
const names = (value, label) => {
  if (value == null || value === "") return "";
  const items = (Array.isArray(value) ? value : String(value).split(","))
    .map((v) => String(v).replace(/[\r\n\t]/g, " ").trim())
    .filter(Boolean);
  if (items.length > 200) throw new Error(`${label}: choose at most 200.`);
  if (items.some((v) => v.length > 300 || v.includes(",")))
    throw new Error(`${label} names cannot contain commas or exceed 300 characters.`);
  return items.join(",");
};

export function findReportTool(explicit = process.env.PULSE_REPORT_TOOL) {
  for (const candidate of [explicit, BUNDLED].filter(Boolean)) {
    const path = resolve(candidate);
    if (existsSync(path)) return path;
  }
  return null;
}

const list = (value, allowed, label) => {
  if (value == null || value === "" || value === "all") return "all";
  const items = (Array.isArray(value) ? value : String(value).split(","))
    .map((v) => String(v).trim().toLowerCase())
    .filter(Boolean);
  if (!items.length || items.some((v) => !allowed.includes(v)))
    throw new Error(`${label} must be all or a list of: ${allowed.join(", ")}.`);
  return [...new Set(items)].join(",");
};
const text = (value, max = 200) =>
  value == null ? "" : String(value).replace(/[\r\n\t]/g, " ").trim().slice(0, max);

/** Validate dashboard options into report-tool flags (never the token). */
export function reportOptions(input = {}) {
  const formats = list(input.formats ?? ["pdf", "html"], FORMATS, "Formats");
  const top = input.top == null || input.top === "" ? "" : String(input.top).trim();
  if (top && top !== "all" && !/^\d{1,5}$/.test(top))
    throw new Error("Top findings must be a number or all.");
  const maxDetail = input.maxDetailRows == null || input.maxDetailRows === "" ? "" : String(input.maxDetailRows);
  if (maxDetail && !/^\d{1,6}$/.test(maxDetail))
    throw new Error("Max detail rows must be a number.");
  const wanted = SOURCE_ALIAS[input.source] || input.source || "csv";
  if (!SOURCES.includes(wanted))
    throw new Error(`Data source must be one of: ${SOURCES.join(", ")}.`);
  const source = wanted;
  // Scope: where an API source reads from. Only the two API sources use it.
  const scope = {};
  if (source === "export" || source === "issues") {
    const region = input.region ? String(input.region).trim().toLowerCase() : "";
    if (region && !REGION.test(region)) throw new Error("Region must be us, us02, eu, au or gov.");
    const group = input.group ? String(input.group).trim() : "";
    const org = input.org ? String(input.org).trim() : "";
    if (group && !UUID.test(group)) throw new Error("Group must be a group ID from the list.");
    if (org && !UUID.test(org)) throw new Error("Organization must be an organization ID from the list.");
    if (group && org && source === "issues") {
      // The Issues API reads one org at a time under a group; both is fine.
    }
    Object.assign(scope, { region, group, org });
    scope.scopeName = text(input.scopeName, 120);
    scope.targets = names(input.targets, "Targets");
    scope.projects = names(input.projects, "Projects");
  }
  // CLI: a local folder to scan, plus which of the two scans to run.
  let cli = null;
  if (source === "cli") {
    const path = input.path ? String(input.path).trim() : "";
    if (!path) throw new Error("Enter the folder to scan.");
    if (!isAbsolute(path) || /[\0\r\n]/.test(path))
      throw new Error("Folder must be an absolute path, for example /Users/you/projects/app.");
    cli = { path, scanners: list(input.cliScanners, ["sast", "sca"], "Scans") };
  }
  // A checkout to read code from, for the API and CSV sources (CLI reads --path).
  let codePath = "";
  if (source !== "cli" && input.codePath) {
    codePath = String(input.codePath).trim();
    if (!isAbsolute(codePath) || /[\0\r\n]/.test(codePath))
      throw new Error("Code folder must be an absolute path.");
  }
  // A preset, or an exact start date; an optional inclusive end date.
  const since = input.since ? String(input.since) : "all";
  if (!SINCE.includes(since) && !realDay(since))
    throw new Error(`Period must be one of ${SINCE.join(", ")} or a date (YYYY-MM-DD).`);
  const until = input.until ? String(input.until) : "";
  const today = new Date().toISOString().slice(0, 10);
  if (until && !realDay(until)) throw new Error("End date must be a date (YYYY-MM-DD).");
  if ((realDay(since) && since > today) || (until && until > today))
    throw new Error("Dates cannot be in the future.");
  if (until && realDay(since) && until < since) throw new Error("End date is before the start date.");
  return {
    source,
    scope,
    cli,
    codePath,
    // Snyk's description and remediation text, read back from the Issues API.
    // On by default; it adds one request per project with a detail page.
    details: input.details !== false,
    dataflow: input.dataflow !== false,
    formats: formats === "all" ? FORMATS.join(",") : formats,
    severity: list(input.severity, SEVERITIES, "Severity"),
    status: list(input.status, STATUSES, "Status"),
    product: list(input.product, PRODUCTS, "Product"),
    since,
    until,
    title: text(input.title) || "Snyk vulnerability report",
    subtitle: text(input.subtitle),
    preparedFor: text(input.preparedFor),
    preparedBy: text(input.preparedBy),
    classification: text(input.classification, 60) || "Confidential",
    top,
    maxDetailRows: maxDetail,
    includeDeleted: !!input.includeDeleted,
  };
}

function flags(options, out, extra) {
  const args = [
    "--out", out,
    "--format", options.formats,
    "--severity", options.severity,
    "--status", options.status,
    "--product", options.product,
    "--title", options.title,
    "--classification", options.classification,
  ];
  for (const [flag, value] of [
    ["--subtitle", options.subtitle],
    ["--prepared-for", options.preparedFor],
    ["--prepared-by", options.preparedBy],
    ["--top", options.top],
    ["--max-detail-rows", options.maxDetailRows],
  ])
    if (value) args.push(flag, value);
  if (options.includeDeleted) args.push("--include-deleted");
  if (!options.details) args.push("--no-details");
  if (!options.dataflow) args.push("--no-dataflow");
  return [...extra, ...args];
}

const PRESET_TEXT = { "7d": "last 7 days", "14d": "last 14 days", "30d": "last 30 days", "90d": "last 90 days", "180d": "last 6 months", "365d": "last 365 days", "2y": "last 2 years", all: "all history" };
function periodText(since, until) {
  const start = PRESET_TEXT[since] || `since ${since}`;
  if (!until) return start;
  return since === "all" ? `up to ${until}` : realDay(since) ? `${since} to ${until}` : `${start}, up to ${until}`;
}

// [from, to] as YYYY-MM-DD (either may be ""), for filtering loaded rows.
function introducedWindow(since, until) {
  let from = "";
  if (realDay(since)) from = since;
  else if (since !== "all") {
    const days = since === "2y" ? 730 : Number(since.replace("d", ""));
    from = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
  }
  return [from, until || ""];
}

const stamp = () => {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
};

/**
 * Report jobs: one at a time, saved under <store>/reports/<id>/ with a
 * meta.json describing how each was produced.
 */
export function createReports({ directory, tool = findReportTool(), node = process.execPath }) {
  const root = join(directory, "reports");
  let job = null;
  let child = null;

  async function listReports() {
    let entries = [];
    try {
      entries = await readdir(root, { withFileTypes: true });
    } catch (error) {
      if (error.code === "ENOENT") return [];
      throw error;
    }
    const reports = [];
    for (const entry of entries) {
      if (!entry.isDirectory() || !ID.test(entry.name)) continue;
      try {
        const meta = JSON.parse(await readFile(join(root, entry.name, "meta.json"), "utf8"));
        const files = [];
        for (const format of FORMATS) {
          try {
            const info = await stat(join(root, entry.name, `report.${format}`));
            files.push({ format, bytes: info.size });
          } catch {}
        }
        reports.push({ ...meta, id: entry.name, files });
      } catch {}
    }
    return reports.sort((a, b) => b.id.localeCompare(a.id));
  }

  /**
   * Start a report. `loaded` is the in-memory issues dataset (headers + rows)
   * for source "loaded"; `api` carries token/region/scope for source "api".
   */
  async function start(options, { loaded, api, onDone } = {}) {
    if (!tool)
      throw Object.assign(new Error("The bundled report generator (vendor/snyk-auto-report.mjs) is missing. Reinstall Pulse, run npm run vendor:report, or start Pulse with --report-tool PATH."), { status: 409 });
    if (job?.running) throw Object.assign(new Error("A report is already being generated."), { status: 409 });
    const id = `${stamp()}-${Math.random().toString(36).slice(2, 6)}`;
    const dir = join(root, id);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const env = { ...process.env, NO_COLOR: "1" };
    delete env.SNYK_TOKEN;
    let extra;
    let sourceLabel;
    if (options.source === "export" || options.source === "issues") {
      // What the form chose wins; the saved connection fills anything it left
      // blank, so a one-click report on the saved scope still works.
      const s = options.scope;
      const region = s.region || api?.region;
      const group = s.group || (s.org ? "" : api?.group);
      const org = s.org || (s.group ? "" : api?.org);
      const token = api?.token;
      if (!token)
        throw Object.assign(new Error("Enter a Snyk token (or pull data from the Snyk API once) to build a report from Snyk."), { status: 409 });
      if (!region || !(org || group))
        throw Object.assign(new Error("Choose a region and an organization or group."), { status: 409 });
      // The token travels in the environment only, never in argv.
      env.SNYK_TOKEN = token;
      extra = [
        options.source === "issues" ? "--from-issues-api" : "--from-api",
        "--region", region,
        // An org is the narrower scope; a group is only used when no org is picked.
        org ? "--org" : "--group", org || group,
        "--since", options.since,
      ];
      if (options.until) extra.push("--until", options.until);
      if (s.targets) extra.push("--target", s.targets);
      if (s.projects) extra.push("--project", s.projects);
      const scopeName = s.org || s.group ? s.scopeName || org || group : api?.scopeName || org || group;
      sourceLabel = `${options.source === "issues" ? "Snyk Issues API (live)" : "Snyk Export API"} · ${scopeName}${s.targets ? ` · ${s.targets.split(",").length} target(s)` : ""} · ${periodText(options.since, options.until)}`;
    } else if (options.source === "cli") {
      // Scans a local folder with the Snyk CLI. The folder must exist; the tool
      // is run without a shell, so the path is only ever one argv element.
      let info;
      try {
        info = await stat(options.cli.path);
      } catch {
        info = null;
      }
      if (!info?.isDirectory())
        throw Object.assign(new Error(`Folder not found: ${options.cli.path}`), { status: 422 });
      // The CLI uses its own login (snyk auth) or SNYK_TOKEN. Pass a token only
      // if one was supplied or saved; otherwise leave it to `snyk auth`.
      if (api?.token) env.SNYK_TOKEN = api.token;
      extra = ["--from-cli", "--path", options.cli.path, "--product", options.cli.scanners];
      if (options.scope?.region || api?.region) extra.push("--region", options.scope?.region || api.region);
      sourceLabel = `Snyk CLI scan · ${options.cli.path}`;
    } else {
      if (!loaded?.rows?.length)
        throw Object.assign(new Error("Load an issues dataset first (CSV or API), or choose a live Snyk report."), { status: 409 });
      // Same period as a live export: keep rows first introduced in the window.
      const [from, to] = introducedWindow(options.since, options.until);
      const rows =
        from || to
          ? loaded.rows.filter((row) => {
              const day = String(row.FIRST_INTRODUCED || "").slice(0, 10);
              return day && (!from || day >= from) && (!to || day <= to);
            })
          : loaded.rows;
      if (!rows.length)
        throw Object.assign(new Error(`No loaded findings were first introduced in ${periodText(options.since, options.until)}.`), { status: 422 });
      const input = join(dir, "input.csv");
      await writeFile(
        input,
        encodeCSV(loaded.headers, rows.map((r) => loaded.headers.map((h) => r[h] ?? ""))),
        { mode: 0o600 },
      );
      extra = ["--csv", input];
      sourceLabel = `Loaded data · ${loaded.source || "CSV import"} · ${periodText(options.since, options.until)} · ${rows.length.toLocaleString()} rows`;
    }
    // A checkout to read the code at each data-flow step from (CLI reads --path).
    if (options.codePath && options.source !== "cli") extra.push("--path", options.codePath);
    const meta = {
      created_at: new Date().toISOString(),
      title: options.title,
      source: options.source,
      source_label: sourceLabel,
      formats: options.formats.split(","),
      filters: { severity: options.severity, status: options.status, product: options.product },
      status: "running",
    };
    await writeFile(join(dir, "meta.json"), JSON.stringify(meta, null, 2), { mode: 0o600 });
    job = { id, running: true, stage: "starting", message: "Starting the report generator…", log: [] };
    const args = [tool, ...flags(options, join(dir, "report"), extra)];
    child = spawn(node, args, { cwd: dir, env, stdio: ["ignore", "ignore", "pipe"] });
    let buffer = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      buffer += chunk;
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop();
      for (const raw of lines) {
        const line = (api?.token ? raw.replaceAll(api.token, "[redacted]") : raw).trimEnd();
        if (!line.trim()) continue;
        job.log.push(line);
        if (job.log.length > 200) job.log.shift();
        // Tool prefixes: "> " step, "  warning: ", "error: ".
        if (/^>\s/.test(line)) job.message = line.replace(/^>\s*/, "");
        else if (/warning:/i.test(line)) job.warnings = [...(job.warnings || []), line.replace(/^\s*warning:\s*/i, "")].slice(-10);
        else if (/^error:/i.test(line)) job.error = line.replace(/^error:\s*/i, "");
        else if (/export .*: /i.test(line)) job.message = line.trim();
      }
    });
    child.once("error", (error) => finish(1, error.message));
    child.once("close", (code, signal) => finish(signal ? 130 : code));
    async function finish(code, spawnError) {
      if (!job?.running || job.id !== id) return;
      child = null;
      await rm(join(dir, "input.csv"), { force: true });
      const produced = (await listReports()).find((r) => r.id === id)?.files || [];
      const missing = meta.formats.filter((f) => !produced.some((p) => p.format === f));
      const cancelled = code === 130;
      const ok = code === 0 && produced.length > 0;
      if (missing.includes("pdf") && ok)
        (job.warnings ||= []).push("PDF was not produced. Install Google Chrome, Chromium or Microsoft Edge, or set CHROME_PATH.");
      meta.status = cancelled ? "cancelled" : ok ? "complete" : "failed";
      meta.finished_at = new Date().toISOString();
      meta.warnings = job.warnings || [];
      if (!ok && !cancelled) meta.error = spawnError || job.error || job.log.slice(-3).join(" · ") || `Report generator exited with code ${code}.`;
      await writeFile(join(dir, "meta.json"), JSON.stringify(meta, null, 2), { mode: 0o600 }).catch(() => {});
      job = {
        ...job,
        running: false,
        stage: meta.status,
        message: cancelled
          ? "Report cancelled."
          : ok
            ? `Report ready: ${produced.map((p) => p.format.toUpperCase()).join(", ")}.`
            : `Report failed: ${meta.error}`,
      };
      if (!ok) await rm(dir, { recursive: true, force: true }).catch(() => {});
      onDone?.(job);
    }
    return { id };
  }

  return {
    available: () => !!tool,
    toolPath: () => tool,
    job: () => job,
    list: listReports,
    start,
    cancel() {
      if (!child) return false;
      child.kill("SIGTERM");
      return true;
    },
    /** Resolve a report file strictly inside the reports directory. */
    async file(id, format) {
      if (!ID.test(id) || !FORMATS.includes(format)) return null;
      const path = join(root, id, `report.${format}`);
      try {
        const info = await stat(path);
        if (!info.isFile()) return null;
        return { path, bytes: await readFile(path), type: MIME[format] };
      } catch {
        return null;
      }
    },
    async remove(id) {
      if (!ID.test(id) || job?.running && job.id === id) return false;
      await rm(join(root, id), { recursive: true, force: true });
      return true;
    },
    close() {
      child?.kill("SIGTERM");
    },
  };
}
