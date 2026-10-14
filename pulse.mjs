#!/usr/bin/env node
import { parseArgs } from "node:util";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { realpathSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import {
  createSession,
  addDatasets,
  demoDataset,
  dashboard,
  restoreVersion,
} from "./lib/session.mjs";
import { DEFAULT_STORE, openStore } from "./lib/store.mjs";
import { validateMetrics } from "./lib/extensions.mjs";
import { findReportTool } from "./lib/reports.mjs";
import { parseCSV, day } from "./lib/csv.mjs";
import { pullDatasets, validateConnection } from "./lib/snyk.mjs";
import { authenticate } from "./lib/connection.mjs";
import { metricsCSV, issuesCSV } from "./lib/server.mjs";
import {
  DEFAULT_PORT,
  startManagedServer,
  stopRunning,
} from "./lib/runtime.mjs";

export const HELP = `Snyk Pulse — one-command security reporting utility (Node 22+)

  node snyk-pulse/pulse.mjs
  node snyk-pulse/pulse.mjs --csv issues.csv
  node snyk-pulse/pulse.mjs --api-key TOKEN --org UUID --region eu
  SNYK_TOKEN=... node snyk-pulse/pulse.mjs --group UUID --datasets issues,usage
  node snyk-pulse/pulse.mjs --csv issues.csv --metrics ./metrics.json
  node snyk-pulse/pulse.mjs --dataset usage=usage.csv --metrics ./usage-metrics.json

Inputs:
  --csv FILE              Complete scoped issues CSV
  --dataset NAME=FILE     Add any registered dataset CSV (repeatable)
  --api-key TOKEN         Personal (My Profile) or group/org service-account token
                         SNYK_TOKEN avoids shell-history exposure
  --org UUID             Pull an organization
  --group UUID           Pull a group (choose one scope)
  --region us|us02|eu|au|gov   Token's region (default us)
  --datasets LIST        Comma-separated API datasets (default issues)
  --from ISO_DATE        Export lower bound (default 1970-01-01; all history)
  --export-id UUID       Resume an existing job (one dataset only)
  --as-of YYYY-MM-DD     CSV snapshot date (default today, UTC)
  --demo                 Load synthetic demo data

Extensions:
  --metrics FILE         JSON array of additional metric definitions
  --registry FILE        JSON array of additional Export API dataset definitions
  --sla FILE             JSON severity-to-days policy

Output:
  --out DIRECTORY        Write metrics.csv and open-issues.csv
  --no-serve             Finish after writing --out (for scripts/CI)
  --no-open              Print launch URL without opening a browser
  --port PORT            Fixed loopback port (default 8780, or the last --port
                         you used); remembered for later launches
  --stop                 Stop this user's managed Pulse instances and exit
  --help                 Show this help

Saved data:
  --store DIRECTORY      Where versions are saved (default ~/.snyk-pulse)
  --no-store             Keep this session in memory only; save nothing
  --forget               Delete saved versions, source and token, then exit

Reports:
  --report-tool FILE     Report generator for Generate report (default: Pulse's
                         bundled vendor/snyk-auto-report.mjs; or PULSE_REPORT_TOOL)

No Python, database service, npm install or build step. Each API pull or CSV
import is saved as a dated version (last 10 kept) in a local SQLite file, and
the next launch reopens the latest one. Use Refresh in the dashboard to pull
the saved API scope again up to today. Ctrl+C stops it.
API setup validates your token, then lists accessible groups and organizations.
Personal: My Profile > Personal access tokens (or legacy API key).
Automation: Group/Organization > Settings > Service accounts.
`;

async function readJSON(path) {
  try {
    const b = await readFile(resolve(path));
    if (b.length > 1024 * 1024) throw new Error();
    return JSON.parse(b.toString("utf8"));
  } catch {
    throw new Error(`Cannot read valid JSON from ${path} (maximum 1 MiB).`);
  }
}

export async function main(
  args = process.argv.slice(2),
  {
    openBrowser = true,
    env = process.env,
    log = console.log,
    pull = pullDatasets,
    auth = authenticate,
    runtimeDirectory,
    onStopped = () => {},
    storeDirectory,
  } = {},
) {
  if (Number(process.versions.node.split(".")[0]) < 22)
    throw new Error("Snyk Pulse requires Node 22 or newer.");
  const { values: v } = parseArgs({
    args,
    strict: true,
    allowPositionals: false,
    options: {
      csv: { type: "string" },
      dataset: { type: "string", multiple: true },
      "api-key": { type: "string" },
      org: { type: "string" },
      group: { type: "string" },
      region: { type: "string", default: "us" },
      datasets: { type: "string", default: "issues" },
      from: { type: "string" },
      "export-id": { type: "string" },
      "as-of": { type: "string" },
      demo: { type: "boolean" },
      metrics: { type: "string" },
      registry: { type: "string" },
      sla: { type: "string" },
      out: { type: "string" },
      "no-serve": { type: "boolean" },
      "no-open": { type: "boolean" },
      port: { type: "string" },
      stop: { type: "boolean" },
      store: { type: "string" },
      "no-store": { type: "boolean" },
      forget: { type: "boolean" },
      "report-tool": { type: "string" },
      help: { type: "boolean", short: "h" },
    },
  });
  if (v.help) {
    log(HELP);
    return;
  }
  let port = v.port === undefined ? null : Number(v.port);
  if (port !== null && (!Number.isInteger(port) || port < 1 || port > 65535))
    throw new Error(
      "Choose a fixed port from 1 to 65535. Port 0 is not supported.",
    );
  if (v.stop) {
    const stopped = await stopRunning({ directory: runtimeDirectory, log });
    log(stopped ? "Pulse stopped." : "No managed Pulse instance is running.");
    return;
  }
  if (v.forget) {
    const store = await openStore(v.store || storeDirectory || DEFAULT_STORE);
    store.clear();
    store.close();
    log(`Saved Pulse data and token deleted from ${store.file}.`);
    return;
  }
  if (v["no-serve"] && !v.out)
    throw new Error("--no-serve requires --out DIRECTORY.");
  if (v.csv && (v.org || v.group))
    throw new Error(
      "Choose --csv or an API scope for the initial issue input.",
    );
  if (v.demo && (v.csv || v.org || v.group || v.dataset?.length))
    throw new Error(
      "--demo cannot be combined with other initial data sources.",
    );
  const session = createSession({
    datasets: v.registry ? await readJSON(v.registry) : [],
    metrics: v.metrics ? await readJSON(v.metrics) : [],
    policy: v.sla ? await readJSON(v.sla) : undefined,
  });
  let store = null;
  if (!v["no-store"]) {
    try {
      store = await openStore(v.store || storeDirectory || DEFAULT_STORE);
    } catch (error) {
      log(`Saved data unavailable: ${error.message}`);
    }
  }
  if (port === null) port = store?.getPort() || DEFAULT_PORT;
  else store?.setPort(port);
  const save = (source, from = null) => {
    if (!store) return;
    store.setSource(source);
    store.setPolicy(session.policy);
    session.version = store.saveVersion(session, { from });
    log(`Saved as version ${session.version}.`);
  };
  const files = new Map();
  if (v.csv) files.set("issues", v.csv);
  for (const item of v.dataset || []) {
    const at = item.indexOf("=");
    if (at < 1 || !item.slice(at + 1))
      throw new Error("--dataset must be NAME=FILE.");
    const name = item.slice(0, at);
    if (files.has(name)) throw new Error(`Dataset ${name} supplied twice.`);
    files.set(name, item.slice(at + 1));
  }
  const incoming = new Map();
  for (const [name, file] of files)
    incoming.set(name, parseCSV(await readFile(resolve(file))));
  if (incoming.size) {
    addDatasets(session, incoming, { asOf: v["as-of"] || day() });
    save({
      kind: "csv",
      dataset: [...files.keys()].join(","),
      fileName: [...files.values()].map((f) => f.split(/[\\/]/).pop()).join(", "),
      asOf: v["as-of"] || day(),
      importedAt: new Date().toISOString(),
    });
  }
  if (v.demo)
    addDatasets(session, new Map([["issues", demoDataset()]]), {
      source: "Synthetic demo",
    });
  let token = v["api-key"] || env.SNYK_TOKEN || "";
  if (v.org || v.group) {
    const options = {
      token,
      org: v.org,
      group: v.group,
      region: v.region,
      datasets: v.datasets.split(",").map((s) => s.trim()),
      from: v.from,
      exportId: v["export-id"],
    };
    validateConnection(options, session.registry);
    log("Validating Snyk token…");
    const { config } = await auth(options);
    log("Token validated. Pulling the selected scope.");
    const output = await pull(
      { ...options, ...config },
      {
        registry: session.registry,
        onProgress: (p) =>
          log(p.message + (p.exportId ? ` · export ${p.exportId}` : "")),
      },
    );
    addDatasets(session, output, { source: "Snyk Export API" });
    store?.setToken(config.token, config.region);
    save(
      {
        kind: "api",
        region: config.region,
        ...(v.group ? { group: v.group } : { org: v.org }),
        datasets: options.datasets,
        from: options.from || "1970-01-01T00:00:00.000Z",
        scopeName: null,
        pulledAt: new Date().toISOString(),
      },
      options.from || "1970-01-01T00:00:00.000Z",
    );
  }
  // Saved custom metrics apply unless --metrics supplied definitions for this run.
  if (store && !v.metrics && store.getMetrics()) {
    try {
      session.definitions = validateMetrics(store.getMetrics(), session.registry);
    } catch (error) {
      log(`Saved custom metrics were not loaded: ${error.message}`);
    }
  }
  // With no new input, reopen the latest saved version.
  if (store && !session.snapshot && !v.demo && !files.size) {
    const latest = store.loadVersion();
    if (latest) {
      restoreVersion(session, latest);
      log(
        `Reopened saved version ${latest.id} (${latest.source}, data as of ${latest.as_of}).`,
      );
    } else if (store.getPolicy()) session.policy = store.getPolicy();
  }
  if (v.out) {
    if (!session.snapshot) throw new Error("--out needs an issues dataset.");
    const result = dashboard(session),
      directory = resolve(v.out);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await writeFile(resolve(directory, "metrics.csv"), metricsCSV(result), {
      mode: 0o600,
    });
    await writeFile(resolve(directory, "open-issues.csv"), issuesCSV(result), {
      mode: 0o600,
    });
    log(`Reports written to ${directory}`);
  }
  if (v["no-serve"]) return { session };
  const running = await startManagedServer(
    session,
    {
      port,
      token,
      region: v.region,
      store,
      ...(v["report-tool"] ? { reportTool: findReportTool(v["report-tool"]) } : {}),
    },
    { directory: runtimeDirectory, log, onStopped },
  );
  token = "";
  log(
    `\nSnyk Pulse utility\n${session.snapshot ? `${session.snapshot.issues.length} issues · ${session.snapshot.source}` : "Choose CSV or API in the browser."}\n\n${running.url}\n\nCtrl+C stops the utility. ${store ? `Data is saved in ${store.file}; the next launch reopens it.` : "Saved data is off; data stays in this process unless you export reports."}`,
  );
  if (openBrowser && !v["no-open"]) {
    // No shell is used. The only argument is our own generated loopback URL.
    const command =
      process.platform === "darwin"
        ? "open"
        : process.platform === "win32"
          ? "rundll32"
          : "xdg-open";
    const params =
      process.platform === "win32"
        ? ["url.dll,FileProtocolHandler", running.url]
        : [running.url];
    const child = spawn(command, params, { stdio: "ignore", detached: true });
    child.once("error", () =>
      log("Open the launch URL above in your browser."),
    );
    child.unref();
  }
  return { ...running, session };
}

let isMain = false;
try {
  isMain =
    !!process.argv[1] &&
    import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
} catch {
  /* Imported from stdin, an evaluator or a test runner. */
}
if (isMain) {
  let running;
  const stop = async () => {
    await running?.close?.();
    process.exit(0);
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
  main(undefined, { onStopped: () => process.exit(0) })
    .then((result) => {
      running = result;
    })
    .catch((error) => {
      const token = process.env.SNYK_TOKEN;
      let message = String(error.message);
      const position = process.argv.indexOf("--api-key");
      for (const secret of [
        token,
        position >= 0 ? process.argv[position + 1] : null,
      ])
        if (secret) message = message.replaceAll(secret, "[redacted]");
      console.error(`Snyk Pulse: ${message}`);
      process.exitCode = 1;
    });
}
