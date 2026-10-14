import { createServer } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { resolve, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { MAX_BYTES, day, encodeCSV, parseCSV } from "./csv.mjs";
import { validatePolicy } from "./metrics.mjs";
import {
  addDatasets,
  applyGroups,
  dashboard,
  demoDataset,
  extensions,
  restoreVersion,
  sessionState,
} from "./session.mjs";
import { validateMetrics, datasetRegistry } from "./extensions.mjs";
import { pullDatasets, validateConnection } from "./snyk.mjs";
import { createReports, reportOptions } from "./reports.mjs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  authenticate,
  discoverConnection,
  discoverGroupOrgs,
  resolveGroups,
} from "./connection.mjs";

const WEB = fileURLToPath(new URL("../web/", import.meta.url));
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".ico": "image/x-icon",
};
const same = (a, b) =>
  typeof a === "string" &&
  Buffer.byteLength(a) === Buffer.byteLength(b) &&
  timingSafeEqual(Buffer.from(a), Buffer.from(b));

async function body(req, limit = MAX_BYTES) {
  if (Number(req.headers["content-length"]) > limit)
    throw Object.assign(new Error("Request exceeds size limit."), {
      status: 413,
    });
  const chunks = [];
  let size = 0;
  for await (const part of req) {
    size += part.length;
    if (size > limit)
      throw Object.assign(new Error("Request exceeds size limit."), {
        status: 413,
      });
    chunks.push(part);
  }
  return Buffer.concat(chunks);
}
const jsonBody = async (req) => {
  try {
    return JSON.parse((await body(req, 1024 * 1024)).toString("utf8"));
  } catch {
    throw new Error("Send valid JSON (maximum 1 MiB).");
  }
};

export function metricsCSV(result) {
  const rows = Object.entries(result.metrics).map(([name, value]) => [
    name,
    value ?? "Unavailable",
    result.period.start,
    result.period.end,
    result.snapshot.as_of,
    JSON.stringify(result.filters),
    JSON.stringify(result.policy),
  ]);
  for (const m of result.custom_metrics || [])
    rows.push([
      `custom:${m.id}`,
      m.value ?? "Unavailable",
      result.period.start,
      result.period.end,
      result.snapshot.as_of,
      JSON.stringify(result.filters),
      JSON.stringify(result.policy),
    ]);
  return encodeCSV(
    [
      "metric",
      "value",
      "period_start",
      "period_end",
      "snapshot_date",
      "scope",
      "sla_policy",
    ],
    rows,
  );
}
export function issuesCSV(result, overSla = false) {
  const fields = [
    "snapshot_date",
    "problem_id",
    "title",
    "org",
    "project",
    "target",
    "target_ref",
    "product",
    "issue_type",
    "cve",
    "cwe",
    "severity",
    "status",
    "age_days",
    "sla_days",
    "over_sla",
    "fixable",
    "fix_version",
    "package",
  ];
  return encodeCSV(
    fields,
    result._all_issues
      .filter((i) => !overSla || i.over_sla)
      .map((i) =>
        fields.map((k) =>
          k === "snapshot_date" ? result.snapshot.as_of : i[k],
        ),
      ),
  );
}

export async function startServer(
  session,
  {
    port = 8780,
    token: initialToken = "",
    region = "us",
    discover = discoverConnection,
    groupOrgs = discoverGroupOrgs,
    pull = pullDatasets,
    auth = authenticate,
    lookupGroups = resolveGroups,
    webRoot = WEB,
    control,
    store = null,
    reportTool,
    onStopped = () => {},
  } = {},
) {
  // Full HTML/PDF/CSV/JSON reports via the snyk_report generator.
  const reports = createReports({
    directory: store?.directory || join(tmpdir(), "snyk-pulse-reports"),
    ...(reportTool !== undefined ? { tool: reportTool } : {}),
  });
  let token = initialToken || store?.getToken()?.token || "";
  if (!initialToken && store?.getToken()?.region) region = store.getToken().region;
  // Persist the current session as a new version; storage failures never lose the live data.
  const save = (source, from = null) => {
    if (!store) return null;
    try {
      if (source) store.setSource(source);
      store.setPolicy(session.policy);
      session.version = store.saveVersion(session, { from });
      return session.version;
    } catch (error) {
      session.storeWarning = "Data loaded but could not be saved: " + error.message;
      return null;
    }
  };
  // Org IDs whose issues carry no group (e.g. Snyk "Issues detail" CSV exports).
  const ungroupedOrgs = () => [
    ...new Set(
      (session.snapshot?.issues || [])
        .filter((i) => !i.group_id || i.group === "Unknown group")
        .map((i) => i.org_id),
    ),
  ];
  let groupLookup = null;
  // Fill missing groups: saved mapping first, then the Snyk API if a token is available.
  async function fillGroups({ useApi = true } = {}) {
    if (store) applyGroups(session, store.getGroups());
    const missing = ungroupedOrgs();
    if (!missing.length || !useApi || !token) return { missing: missing.length };
    groupLookup = { running: true };
    try {
      const { mapping, config } = await lookupGroups({ token, region });
      token = config.token;
      if (store) store.setGroups({ ...store.getGroups(), ...mapping });
      const updated = applyGroups(session, mapping);
      const left = ungroupedOrgs().length;
      groupLookup = {
        running: false,
        message: left
          ? `${left} org(s) are not visible to this token, so their group is unknown.`
          : null,
      };
      return { updated, missing: left };
    } catch (error) {
      groupLookup = {
        running: false,
        message: "Group lookup failed: " + String(error.message).replaceAll(token, "[redacted]"),
      };
      return { missing: missing.length, error: groupLookup.message };
    }
  }
  // Restored/CLI-loaded data: fill groups in the background without blocking startup.
  void fillGroups().catch(() => {});
  let connection = null,
    connectionConfig = null,
    validating = false;
  let closing,
    pullContext = null;
  function runPull(context) {
    const controller = new AbortController();
    session.controller = controller;
    session.job = {
      running: true,
      stage: "starting",
      message: "Preparing selected exports.",
    };
    let downloaded = false;
    void Promise.resolve()
      .then(() =>
        pull(context.options, {
          registry: context.registry,
          checkpoint: context.checkpoint,
          signal: controller.signal,
          onProgress: (p) => {
            session.job = { running: true, ...p };
          },
        }),
      )
      .then((result) => {
        downloaded = true;
        if (closing || controller.signal.aborted)
          throw new Error("Export cancelled.");
        addDatasets(session, result, { source: "Snyk Export API" });
        const { org, group, datasets, from } = context.options;
        const saved = save(
          {
            kind: "api",
            region: context.options.region,
            ...(group ? { group } : { org }),
            datasets: datasets || ["issues"],
            from: from || "1970-01-01T00:00:00.000Z",
            scopeName: context.scopeName || null,
            pulledAt: new Date().toISOString(),
          },
          from || "1970-01-01T00:00:00.000Z",
        );
        pullContext = null;
        session.job = {
          running: false,
          stage: "complete",
          message:
            "All selected datasets loaded." +
            (saved ? ` Saved as version ${saved}.` : ""),
        };
      })
      .catch((error) => {
        const canResume =
          !closing &&
          !downloaded &&
          context.checkpoint.exports.size > 0 &&
          !error.submissionUncertain &&
          !error.terminalExport &&
          !error.nonResumable;
        session.job = {
          ...session.job,
          running: false,
          failedStage: session.job?.stage,
          stage: "error",
          canResume,
          message:
            controller.signal.aborted && !error.submissionUncertain
              ? "Export cancelled locally." +
                (canResume ? " The Snyk export can still be resumed." : "")
              : String(error.message).replaceAll(
                  context.options.token,
                  "[redacted]",
                ),
        };
        if (!canResume) pullContext = null;
      });
  }
  // Build an exact route manifest from the trusted bundle at startup. Request
  // paths never become filesystem paths or executable/HTML response content.
  const assets = new Map();
  async function loadAssets(directory, prefix = "") {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      if (error.code === "ENOENT") return;
      throw error;
    }
    for (const entry of entries) {
      const file = resolve(directory, entry.name),
        route = prefix + "/" + entry.name;
      if (entry.isDirectory()) await loadAssets(file, route);
      else if (entry.isFile() && Object.hasOwn(MIME, extname(entry.name)))
        assets.set(route, {
          bytes: await readFile(file),
          type: MIME[extname(entry.name)],
        });
    }
  }
  await loadAssets(resolve(webRoot));
  if (assets.has("/index.html")) assets.set("/", assets.get("/index.html"));
  const secret = randomBytes(24).toString("hex");
  const server = createServer(async (req, res) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
    );
    const send = (status, data, type = "application/json; charset=utf-8") => {
      res.writeHead(status, { "Content-Type": type });
      res.end(
        type.startsWith("application/json") ? JSON.stringify(data) : data,
      );
    };
    try {
      const host = `127.0.0.1:${server.address().port}`;
      if (req.headers.host !== host)
        return send(403, {
          detail: "Use the loopback URL printed by the utility.",
        });
      const url = new URL(req.url, `http://${host}`),
        path = url.pathname,
        query = Object.fromEntries(url.searchParams);
      if (path === "/api/health")
        return send(200, {
          status: "ok",
          app: "snyk-pulse-utility",
          mode: "node-utility",
          version: "0.2.0",
          ...(control ? { instanceId: control.instanceId } : {}),
        });
      if (path === "/api/runtime/stop" && control) {
        if (
          req.method !== "POST" ||
          req.headers.origin ||
          req.headers["sec-fetch-site"] ||
          !same(req.headers["x-pulse-control"], control.token)
        )
          return send(403, {
            detail: "Only the local Pulse launcher can stop this instance.",
          });
        req.resume();
        res.once("finish", () => {
          void close()
            .then(onStopped)
            .catch(() => {});
        });
        return send(202, { status: "stopping" });
      }
      if (req.method === "GET" && same(path, `/launch/${secret}`)) {
        res.writeHead(303, {
          "Set-Cookie": `pulse_session=${secret}; HttpOnly; SameSite=Strict; Path=/`,
          Location: "/",
        });
        res.end();
        return;
      }
      const cookie = req.headers.cookie
        ?.split(";")
        .map((x) => x.trim())
        .find((x) => x.startsWith("pulse_session="))
        ?.slice(14);
      if (!same(cookie, secret))
        return path.startsWith("/api")
          ? send(401, {
              detail: "Open the launch URL printed in your terminal.",
            })
          : send(
              401,
              "Open the launch URL printed by Snyk Pulse in your terminal.",
              "text/plain; charset=utf-8",
            );
      if (req.headers.origin && req.headers.origin !== `http://${host}`)
        return send(403, { detail: "Cross-origin access is disabled." });
      if (req.headers["sec-fetch-site"] === "cross-site")
        return send(403, { detail: "Cross-site access is disabled." });
      if (
        !["GET", "HEAD"].includes(req.method) &&
        req.headers["x-pulse-local"] !== "1"
      )
        return send(403, { detail: "Local mutation header required." });
      if (req.method === "GET" && path === "/api/state")
        return send(200, {
          ...sessionState(session),
          hasToken: !!token,
          connectionRegion: region,
          store: store
            ? {
                enabled: true,
                location: store.file,
                source: store.getSource(),
                tokenSaved: !!store.getToken(),
                warning: session.storeWarning || null,
              }
            : { enabled: false },
          workspaceName: store?.getWorkspaceName() || null,
          groupLookup: {
            ...(groupLookup || { running: false, message: null }),
            missing: ungroupedOrgs().length,
          },
        });
      if (req.method === "PUT" && path === "/api/workspace") {
        const { name } = await jsonBody(req);
        if (name != null && (typeof name !== "string" || name.length > 120))
          throw new Error("Workspace name must be text up to 120 characters.");
        if (!store) return send(409, { detail: "Saved data is disabled (--no-store)." });
        store.setWorkspaceName(name?.trim() || null);
        return send(200, { name: store.getWorkspaceName() });
      }
      if (req.method === "POST" && path === "/api/groups/lookup") {
        if (session.job?.running || validating || groupLookup?.running)
          return send(409, { detail: "Wait for the current Snyk request to finish." });
        const supplied = await jsonBody(req);
        if (supplied.token) {
          token = String(supplied.token);
          if (supplied.region) region = String(supplied.region);
        }
        if (!token)
          return send(409, {
            detail: "Enter a Snyk token to look up groups. It is saved for next time.",
            needsToken: true,
          });
        const result = await fillGroups();
        if (result.error) return send(422, { detail: result.error });
        store?.setToken(token, region);
        session.revision++;
        return send(200, result);
      }
      if (req.method === "GET" && path === "/api/reports/generated")
        return send(200, {
          available: reports.available(),
          tool: reports.toolPath(),
          job: reports.job(),
          reports: await reports.list(),
          canUseApi: store?.getSource()?.kind === "api" && !!token,
          loadedRows: session.datasets.get("issues")?.rows.length || 0,
        });
      if (req.method === "POST" && path === "/api/reports/generate") {
        const options = reportOptions(await jsonBody(req));
        const saved = store?.getSource();
        const issues = session.datasets.get("issues");
        const started = await reports.start(options, {
          loaded: issues && { ...issues, source: session.snapshot?.source },
          api:
            saved?.kind === "api"
              ? { token, region: saved.region, org: saved.org, group: saved.group, scopeName: saved.scopeName }
              : null,
        });
        return send(202, started);
      }
      if (req.method === "POST" && path === "/api/reports/generated/cancel") {
        req.resume();
        return send(200, { cancelled: reports.cancel() });
      }
      if (path.startsWith("/api/reports/generated/")) {
        const [id, format] = path.slice("/api/reports/generated/".length).split("/");
        if (req.method === "DELETE" && !format)
          return (await reports.remove(id))
            ? send(200, { deleted: id })
            : send(404, { detail: "Report not found or still running." });
        if (req.method === "GET" && format) {
          const file = await reports.file(id, format);
          if (!file) return send(404, { detail: "Report file not found." });
          // HTML reports open in the browser; other formats download.
          if (format !== "html" || query.download === "1")
            res.setHeader("Content-Disposition", `attachment; filename="snyk-report-${id}.${format}"`);
          if (format === "html")
            // The generated report is self-contained static HTML: allow its inline styles/images, no scripts.
            res.setHeader(
              "Content-Security-Policy",
              "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; frame-ancestors 'none'",
            );
          return send(200, file.bytes, file.type);
        }
      }
      if (req.method === "GET" && path === "/api/versions")
        return send(200, store ? store.listVersions() : []);
      if (req.method === "POST" && path === "/api/versions/restore") {
        if (!store) return send(409, { detail: "Saved data is disabled (--no-store)." });
        if (session.job?.running)
          return send(409, { detail: "Wait for the API pull before switching versions." });
        const { id } = await jsonBody(req);
        const version = store.loadVersion(Number(id));
        if (!version) return send(404, { detail: "That version no longer exists." });
        restoreVersion(session, version);
        session.revision++;
        void fillGroups().catch(() => {});
        return send(200, { version: version.id, count: session.snapshot?.issues.length || 0 });
      }
      if (req.method === "DELETE" && path.startsWith("/api/versions/")) {
        if (!store) return send(409, { detail: "Saved data is disabled (--no-store)." });
        const id = Number(path.slice("/api/versions/".length));
        if (!Number.isInteger(id) || !store.deleteVersion(id))
          return send(404, { detail: "That version no longer exists." });
        return send(200, { deleted: id });
      }
      if (req.method === "POST" && path === "/api/refresh") {
        if (session.job?.running || validating)
          return send(409, { detail: "Wait for the current Snyk request to finish." });
        const supplied = await jsonBody(req);
        const saved = store?.getSource();
        if (saved?.kind !== "api")
          return send(409, {
            detail:
              "Refresh repeats the last Snyk API pull. CSV data can only be refreshed by importing a newer file.",
          });
        // Refresh always pulls the full window up to now: from the original
        // start, or from an explicit start date the user picked.
        let from = saved.from;
        if (supplied.from) {
          if (!/^\d{4}-\d{2}-\d{2}$/.test(supplied.from) || supplied.from > day())
            throw new Error("Choose a refresh start date on or before today.");
          from = supplied.from + "T00:00:00.000Z";
        }
        if (supplied.token) token = String(supplied.token);
        if (!token)
          return send(409, {
            detail: "Enter your Snyk token to refresh. It will be saved for next time.",
            needsToken: true,
          });
        validating = true;
        let config;
        try {
          ({ config } = await auth({ token, region: saved.region }));
        } catch (error) {
          if (error.status === 401)
            return send(409, {
              detail: "The saved Snyk token was rejected. Enter a new token to refresh.",
              needsToken: true,
            });
          throw error;
        } finally {
          validating = false;
        }
        token = config.token;
        region = config.region;
        store?.setToken(token, region);
        const options = {
          ...config,
          ...(saved.group ? { group: saved.group } : { org: saved.org }),
          datasets: saved.datasets.filter((d) => Object.hasOwn(session.registry, d)),
          from,
        };
        validateConnection(options, session.registry);
        pullContext = {
          options,
          registry: session.registry,
          identity: null,
          scopeName: saved.scopeName,
          checkpoint: { exports: new Map(), completed: new Map() },
        };
        runPull(pullContext);
        return send(202, { status: "started", from });
      }
      if (req.method === "GET" && path === "/api/job")
        return send(200, session.job);
      if (req.method === "GET" && path === "/api/extensions")
        return send(200, extensions(session, query));
      if (req.method === "GET" && path === "/api/issues") {
        // One page of the open-findings work list, searched/filtered over the full scope.
        const {
          search = "",
          mode = "all",
          offset = "0",
          limit = "100",
          t_severity = "",
          t_product = "",
          t_org = "",
          t_type = "",
          t_target = "",
          ...scope
        } = query;
        const start = Math.max(0, Number.parseInt(offset, 10) || 0),
          size = Math.min(500, Math.max(1, Number.parseInt(limit, 10) || 100));
        if (!["all", "over", "fixable"].includes(mode))
          throw new Error("Issue filter must be all, over or fixable.");
        if (!session.snapshot) return send(200, { issues: [], total: 0, offset: 0 });
        const needle = String(search).toLowerCase().slice(0, 200);
        const all = dashboard(session, scope)._all_issues;
        // Table-only filters narrow the work list without changing dashboard metrics.
        const table = { severity: t_severity, product: t_product, org_id: t_org, issue_type: t_type, target: t_target };
        const rows = all.filter(
          (i) =>
            (mode === "all" || (mode === "over" ? i.over_sla : i.fixable)) &&
            Object.entries(table).every(([k, v]) => !v || i[k] === v) &&
            (!needle ||
              `${i.title} ${i.project} ${i.problem_id} ${i.package || ""} ${i.cve} ${i.cwe} ${i.target}`
                .toLowerCase()
                .includes(needle)),
        );
        // Choices come from the full open list in scope, so options never vanish while filtering.
        const choices = (field) => [...new Set(all.map((i) => i[field]).filter(Boolean))].sort();
        return send(200, {
          issues: rows.slice(start, start + size),
          total: rows.length,
          offset: start,
          ...(start === 0
            ? {
                options: {
                  severity: ["critical", "high", "medium", "low"].filter((v) =>
                    all.some((i) => i.severity === v),
                  ),
                  product: choices("product"),
                  issue_type: choices("issue_type"),
                  target: choices("target"),
                  org: [...new Map(all.map((i) => [i.org_id, i.org]))]
                    .map(([value, label]) => ({ value, label }))
                    .sort((a, b) => a.label.localeCompare(b.label)),
                },
              }
            : {}),
        });
      }
      if (req.method === "GET" && path === "/api/dashboard") {
        const result = dashboard(session, query);
        delete result._all_issues;
        return send(200, result);
      }
      if (req.method === "GET" && path === "/api/demo.csv") {
        const demo = demoDataset();
        res.setHeader(
          "Content-Disposition",
          'attachment; filename="pulse-demo.csv"',
        );
        return send(
          200,
          encodeCSV(
            demo.headers,
            demo.rows.map((r) => demo.headers.map((h) => r[h])),
          ),
          "text/csv; charset=utf-8",
        );
      }
      if (req.method === "POST" && path === "/api/demo") {
        if (session.snapshot || session.job?.running)
          return send(409, { detail: "Demo requires an empty, idle session." });
        addDatasets(session, new Map([["issues", demoDataset()]]), {
          source: "Synthetic demo",
        });
        save({ kind: "demo" });
        return send(200, { count: session.snapshot.issues.length });
      }
      if (req.method === "POST" && path === "/api/import") {
        if (session.job?.running)
          return send(409, {
            detail: "Wait for the API pull or cancel it before importing.",
          });
        const dataset = query.dataset || "issues";
        if (!Object.hasOwn(session.registry, dataset))
          throw new Error("Register this dataset before importing it.");
        if (!(req.headers["content-type"] || "").startsWith("text/csv"))
          return send(415, { detail: "Send a text/csv body." });
        const parsed = parseCSV(await body(req));
        addDatasets(session, new Map([[dataset, parsed]]), {
          asOf: query.as_of || day(),
        });
        save({
          kind: "csv",
          dataset,
          fileName: String(query.file_name || "").slice(0, 200) || null,
          asOf: query.as_of || day(),
          importedAt: new Date().toISOString(),
        });
        void fillGroups().catch(() => {});
        return send(200, {
          version: session.version ?? null,
          count:
            dataset === "issues"
              ? session.snapshot.issues.length
              : parsed.rows.length,
          excluded_deleted: session.snapshot?.excluded_deleted || 0,
          duplicates: session.snapshot?.duplicates || 0,
        });
      }
      if (req.method === "PUT" && path === "/api/policy") {
        session.policy = validatePolicy(await jsonBody(req));
        store?.setPolicy(session.policy);
        return send(200, session.policy);
      }
      if (req.method === "GET" && path === "/api/columns") {
        // Column names with a few distinct sample values, to help write metric definitions.
        const data = session.datasets.get(query.dataset || "issues");
        if (!data) return send(404, { detail: "Dataset is not loaded." });
        const columns = data.headers.map((name) => {
          const seen = new Map();
          for (const row of data.rows) {
            const value = String(row[name] ?? "").trim();
            if (!value) continue;
            seen.set(value, (seen.get(value) || 0) + 1);
            if (seen.size > 200) break;
          }
          const samples = [...seen]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5)
            .map(([value]) => value.slice(0, 60));
          const numeric =
            samples.length > 0 && samples.every((v) => Number.isFinite(Number(v)));
          return { name, samples, numeric, filled: seen.size > 0 };
        });
        return send(200, { dataset: query.dataset || "issues", rows: data.rows.length, columns });
      }
      if (req.method === "PUT" && path === "/api/metrics") {
        session.definitions = validateMetrics(
          await jsonBody(req),
          session.registry,
        );
        store?.setMetrics(session.definitions);
        return send(200, { count: session.definitions.length });
      }
      if (req.method === "POST" && path === "/api/registry") {
        if (session.job?.running)
          return send(409, {
            detail: "Wait for the API pull before changing the registry.",
          });
        const extra = await jsonBody(req);
        const builtins = datasetRegistry();
        const existing = Object.values(session.registry).filter(
          (d) => !Object.hasOwn(builtins, d.name),
        );
        session.registry = datasetRegistry([...existing, ...extra]);
        return send(200, { count: Object.keys(session.registry).length });
      }
      if (req.method === "POST" && path === "/api/connection/validate") {
        if (session.job?.running || validating)
          return send(409, {
            detail: "Wait for the current Snyk request to finish.",
          });
        const supplied = await jsonBody(req);
        if (session.job?.running || validating)
          return send(409, {
            detail: "Wait for the current Snyk request to finish.",
          });
        validating = true;
        connection = null;
        connectionConfig = null;
        try {
          const result = await discover({
            token: supplied.token || token,
            region: supplied.region || region,
          });
          connectionConfig = result.config;
          token = result.config.token;
          region = result.config.region;
          store?.setToken(token, region);
          connection = {
            ...result.connection,
            id: randomBytes(16).toString("hex"),
          };
          return send(200, connection);
        } finally {
          validating = false;
        }
      }
      if (req.method === "POST" && path === "/api/connection/orgs") {
        if (validating || session.job?.running)
          return send(409, {
            detail: "Wait for the current Snyk request to finish.",
          });
        const supplied = await jsonBody(req);
        if (session.job?.running || validating)
          return send(409, {
            detail: "Wait for the current Snyk request to finish.",
          });
        if (!connection || supplied.connectionId !== connection.id)
          return send(409, {
            detail: "Validate your token again before loading organizations.",
          });
        if (!connection.groups.some((g) => g.id === supplied.group))
          throw new Error("Choose a group from the discovered list.");
        validating = true;
        try {
          return send(200, await groupOrgs(connectionConfig, supplied.group));
        } finally {
          validating = false;
        }
      }
      if (req.method === "POST" && path === "/api/connect") {
        if (session.job?.running)
          return send(409, { detail: "An API pull is already running." });
        const supplied = await jsonBody(req);
        if (session.job?.running)
          return send(409, { detail: "An API pull is already running." });
        if (
          validating ||
          !connection ||
          supplied.connectionId !== connection.id
        )
          return send(409, {
            detail:
              "Validate your token and select a scope before pulling data.",
          });
        const options = {
          ...supplied,
          ...connectionConfig,
          // The validated in-memory credential is authoritative for this pull.
          region: connection.region,
        };
        validateConnection(options, session.registry);
        // Kept only in this process; never returned to the browser or serialized.
        token = options.token;
        // Resume state, credentials and completed data stay private to this process.
        const scopeId = options.group || options.org;
        pullContext = {
          options,
          registry: session.registry,
          identity: connection.identity.id,
          scopeName:
            [...connection.groups, ...connection.orgs].find((s) => s.id === scopeId)
              ?.name || null,
          checkpoint: { exports: new Map(), completed: new Map() },
        };
        runPull(pullContext);
        return send(202, { status: "started" });
      }
      if (req.method === "POST" && path === "/api/resume") {
        req.resume();
        if (session.job?.running || validating)
          return send(409, {
            detail: "Wait for the current Snyk request to finish.",
          });
        if (!session.job?.canResume || !pullContext)
          return send(409, {
            detail: "There is no interrupted export to resume in this session.",
          });
        if (
          pullContext.identity &&
          (!connection ||
            connection.identity.id !== pullContext.identity ||
            connection.region !== pullContext.options.region)
        )
          return send(409, {
            detail:
              "Validate the original account in the same region before resuming this export.",
          });
        if (connectionConfig)
          pullContext.options = { ...pullContext.options, ...connectionConfig };
        runPull(pullContext);
        return send(202, { status: "resumed" });
      }
      if (req.method === "POST" && path === "/api/cancel") {
        session.controller?.abort();
        return send(200, { status: "cancelling" });
      }
      if (req.method === "GET" && path === "/api/reports/metrics.csv") {
        res.setHeader(
          "Content-Disposition",
          'attachment; filename="pulse-metrics.csv"',
        );
        return send(
          200,
          metricsCSV(dashboard(session, query)),
          "text/csv; charset=utf-8",
        );
      }
      if (req.method === "GET" && path === "/api/reports/issues.csv") {
        res.setHeader(
          "Content-Disposition",
          'attachment; filename="pulse-open-issues.csv"',
        );
        return send(
          200,
          issuesCSV(dashboard(session, query), query.over_sla === "true"),
          "text/csv; charset=utf-8",
        );
      }
      if (
        req.method === "GET" &&
        path.startsWith("/api/datasets/") &&
        path.endsWith(".csv")
      ) {
        const name = path.slice("/api/datasets/".length, -4),
          dataset = session.datasets.get(name);
        if (!dataset) return send(404, { detail: "Dataset is not loaded." });
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="pulse-${name}.csv"`,
        );
        return send(
          200,
          encodeCSV(
            dataset.headers,
            dataset.rows.map((r) => dataset.headers.map((h) => r[h])),
          ),
          "text/csv; charset=utf-8",
        );
      }
      if (path.startsWith("/api/"))
        return send(404, { detail: "Unknown utility endpoint." });
      if (req.method !== "GET" && req.method !== "HEAD")
        return send(405, { detail: "Method not allowed." });
      const asset = assets.get(decodeURIComponent(path));
      if (!asset)
        return send(404, {
          detail: "Bundled UI file not found. Use the complete release folder.",
        });
      return send(200, req.method === "HEAD" ? "" : asset.bytes, asset.type);
    } catch (error) {
      if (res.headersSent) {
        res.end();
        return;
      }
      const message =
        error.code === "ENOENT"
          ? "Bundled UI file not found. Run the maintainer build or use the complete release folder."
          : String(error.message || "Request failed.");
      send(error.code === "ENOENT" ? 404 : error.status || 422, {
        detail: token ? message.replaceAll(token, "[redacted]") : message,
      });
    }
  });
  server.requestTimeout = 120_000;
  server.headersTimeout = 15_000;
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", resolve);
  });
  const url = `http://127.0.0.1:${server.address().port}/launch/${secret}`;
  function close() {
    if (!closing)
      closing = (async () => {
        session.controller?.abort();
        reports.close();
        token = "";
        connectionConfig = null;
        connection = null;
        pullContext = null;
        server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
        try {
          store?.close();
        } catch {}
      })();
    return closing;
  }
  return { server, url, close };
}
