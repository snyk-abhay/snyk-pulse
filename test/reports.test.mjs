import assert from "node:assert/strict";
import test from "node:test";
import { listTargets } from "../lib/connection.mjs";
import { reportOptions } from "../lib/reports.mjs";

const ORG = "173a8c27-6d91-4bde-9f9d-60a784af2349";
const GROUP = "0dcc9e3d-9e9f-4c76-9d46-0ca2196d3459";

test("legacy source names still work", () => {
  assert.equal(reportOptions({ source: "api" }).source, "export");
  assert.equal(reportOptions({ source: "loaded" }).source, "csv");
  assert.equal(reportOptions({}).source, "csv");
});

test("all four sources are accepted, anything else is not", () => {
  for (const source of ["export", "issues", "csv"])
    assert.equal(reportOptions({ source }).source, source);
  assert.equal(reportOptions({ source: "cli", path: "/tmp" }).source, "cli");
  assert.throws(() => reportOptions({ source: "sql" }), /Data source/);
});

test("scope carries region, org, group, targets and projects for API sources", () => {
  const o = reportOptions({
    source: "issues", region: "EU", org: ORG, group: GROUP,
    targets: ["snyk-abhay/worldmonitor", " snyk-abhay/snyk-scripts "], projects: "a:package.json",
  });
  assert.equal(o.scope.region, "eu");
  assert.equal(o.scope.org, ORG);
  assert.equal(o.scope.targets, "snyk-abhay/worldmonitor,snyk-abhay/snyk-scripts");
  assert.equal(o.scope.projects, "a:package.json");
});

test("scope is rejected when it is not an id from the lists", () => {
  assert.throws(() => reportOptions({ source: "export", org: "not-a-uuid" }), /Organization/);
  assert.throws(() => reportOptions({ source: "export", group: "../etc" }), /Group/);
  assert.throws(() => reportOptions({ source: "export", region: "mars" }), /Region/);
});

test("a target name with a comma cannot split into two flags", () => {
  assert.throws(() => reportOptions({ source: "export", targets: [`a,b`] }), /commas/);
});

test("CLI needs an absolute, existing-looking folder and valid scan list", () => {
  assert.throws(() => reportOptions({ source: "cli" }), /folder/i);
  assert.throws(() => reportOptions({ source: "cli", path: "relative/dir" }), /absolute/);
  assert.throws(() => reportOptions({ source: "cli", path: "/tmp\n--evil" }), /absolute/);
  assert.equal(reportOptions({ source: "cli", path: "/tmp", cliScanners: ["sast"] }).cli.scanners, "sast");
  assert.throws(() => reportOptions({ source: "cli", path: "/tmp", cliScanners: ["x"] }), /Scans/);
});

test("scope is ignored for CSV and CLI sources", () => {
  assert.deepEqual(reportOptions({ source: "csv", org: ORG }).scope, {});
});

test("details and data flow default on and can be switched off", () => {
  const on = reportOptions({});
  assert.equal(on.details, true);
  assert.equal(on.dataflow, true);
  const off = reportOptions({ details: false, dataflow: false });
  assert.equal(off.details, false);
  assert.equal(off.dataflow, false);
});

test("a code folder must be absolute", () => {
  assert.equal(reportOptions({ source: "export", codePath: "/Users/me/app" }).codePath, "/Users/me/app");
  assert.throws(() => reportOptions({ source: "export", codePath: "app" }), /absolute/);
});

test("listTargets asks for empty targets too, and reads display_name", async () => {
  const seen = [];
  const fetchImpl = async (url) => {
    seen.push(String(url));
    return new Response(
      JSON.stringify({
        data: [
          { id: "11111111-1111-1111-1111-111111111111", attributes: { display_name: "snyk-abhay/worldmonitor" } },
          { id: "22222222-2222-2222-2222-222222222222", attributes: { display_name: "snyk-abhay/snyk-scripts" } },
        ],
        links: {},
      }),
      { status: 200, headers: { "content-type": "application/vnd.api+json" } },
    );
  };
  const r = await listTargets({ token: "tok-123456789", region: "us" }, ORG, { fetchImpl });
  // list() sorts by name, which suits a picker.
  assert.deepEqual(r.targets.map((t) => t.name), ["snyk-abhay/snyk-scripts", "snyk-abhay/worldmonitor"]);
  const u = new URL(seen[0]);
  assert.equal(u.pathname, `/rest/orgs/${ORG}/targets`);
  assert.equal(u.searchParams.get("exclude_empty"), "false");
  assert.equal(u.searchParams.get("limit"), "100");
  assert.equal(u.searchParams.getAll("version").length, 1);
});

test("listTargets rejects an organization that is not a UUID", async () => {
  await assert.rejects(() => listTargets({ token: "tok-123456789" }, "../x"), /UUID/);
});

// ---- start(): the flags and environment each source produces ---------------
import { mkdtemp, readFile, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createReports } from "../lib/reports.mjs";

/** A stand-in report tool that records its argv and SNYK_TOKEN, then writes a report. */
async function fakeTool() {
  const dir = await mkdtemp(join(tmpdir(), "pulse-rep-"));
  const tool = join(dir, "tool.mjs");
  await writeFile(
    tool,
    `import { writeFileSync } from "node:fs";
     const out = process.argv[process.argv.indexOf("--out") + 1];
     writeFileSync("seen.json", JSON.stringify({ argv: process.argv.slice(2), token: process.env.SNYK_TOKEN || null }));
     writeFileSync(out + ".html", "<html></html>");`,
  );
  await chmod(tool, 0o755);
  return { dir, tool };
}

async function run(options, ctx) {
  const { dir, tool } = await fakeTool();
  const reports = createReports({ directory: dir, tool });
  const { id } = await reports.start(reportOptions({ formats: ["html"], ...options }), ctx);
  for (let i = 0; i < 100 && reports.job()?.running; i++) await new Promise((r) => setTimeout(r, 50));
  const seen = JSON.parse(await readFile(join(dir, "reports", id, "seen.json"), "utf8"));
  return { ...seen, flag: (f) => seen.argv[seen.argv.indexOf(f) + 1], has: (f) => seen.argv.includes(f) };
}

const API = { token: "tok-secret-123456", region: "us" };

test("export: --from-api with the chosen org, targets and period; token only in env", async () => {
  const r = await run({ source: "export", org: ORG, targets: "a/b,c/d", since: "30d", region: "eu" }, { api: API });
  assert.ok(r.has("--from-api") && !r.has("--from-issues-api"));
  assert.equal(r.flag("--org"), ORG);
  assert.equal(r.flag("--region"), "eu");
  assert.equal(r.flag("--target"), "a/b,c/d");
  assert.equal(r.flag("--since"), "30d");
  assert.equal(r.token, "tok-secret-123456");
  assert.ok(!r.argv.join(" ").includes("tok-secret"), "the token must never appear in argv");
});

test("issues: --from-issues-api, and a group scope when no org is chosen", async () => {
  const r = await run({ source: "issues", group: GROUP }, { api: API });
  assert.ok(r.has("--from-issues-api") && !r.has("--from-api"));
  assert.equal(r.flag("--group"), GROUP);
  assert.ok(!r.has("--org"));
});

test("an org wins over a group when both are sent", async () => {
  const r = await run({ source: "export", org: ORG, group: GROUP }, { api: API });
  assert.equal(r.flag("--org"), ORG);
  assert.ok(!r.has("--group"));
});

test("the saved scope fills in when the form chose none", async () => {
  const r = await run({ source: "export" }, { api: { ...API, org: ORG } });
  assert.equal(r.flag("--org"), ORG);
});

test("an API source with no token or no scope fails clearly", async () => {
  const { dir, tool } = await fakeTool();
  const reports = createReports({ directory: dir, tool });
  await assert.rejects(() => reports.start(reportOptions({ source: "export", org: ORG }), { api: null }), /token/i);
  await assert.rejects(() => reports.start(reportOptions({ source: "export" }), { api: { token: "tok-123456789" } }), /region|organization/i);
});

test("cli: --from-cli with --path and the chosen scans", async () => {
  const folder = await mkdtemp(join(tmpdir(), "pulse-scan-"));
  const r = await run({ source: "cli", path: folder, cliScanners: ["sast"] }, { api: null });
  assert.ok(r.has("--from-cli"));
  assert.equal(r.flag("--path"), folder);
  assert.equal(r.flag("--product"), "sast");
  assert.equal(r.token, null, "no token is invented for the CLI");
});

test("cli: a folder that does not exist is refused before anything runs", async () => {
  const { dir, tool } = await fakeTool();
  const reports = createReports({ directory: dir, tool });
  await assert.rejects(
    () => reports.start(reportOptions({ source: "cli", path: "/definitely/not/here" }), { api: null }),
    /Folder not found/,
  );
});

test("csv: the loaded rows go in as a file", async () => {
  const loaded = { headers: ["PROBLEM_ID", "FIRST_INTRODUCED"], rows: [{ PROBLEM_ID: "x", FIRST_INTRODUCED: "2026-01-01" }] };
  const r = await run({ source: "csv" }, { loaded });
  assert.ok(r.has("--csv"));
});

test("details off adds --no-details; a code folder adds --path for API sources", async () => {
  const r = await run({ source: "export", org: ORG, details: false, dataflow: false, codePath: "/Users/me/app" }, { api: API });
  assert.ok(r.has("--no-details") && r.has("--no-dataflow"));
  assert.equal(r.flag("--path"), "/Users/me/app");
  const d = await run({ source: "export", org: ORG }, { api: API });
  assert.ok(!d.has("--no-details"));
});

// ---- the server: a saved token must not leak into a local CLI scan ---------
import { startServer } from "../lib/server.mjs";
import { createSession } from "../lib/session.mjs";

test("a CLI scan gets no token unless one is typed for it", async () => {
  const { dir, tool } = await fakeTool();
  const folder = await mkdtemp(join(tmpdir(), "pulse-scan-"));
  const s = await startServer(createSession(), { port: 0, store: null, token: "saved-token-123456", reportTool: tool });
  try {
    const launch = await fetch(s.url, { redirect: "manual" });
    const cookie = launch.headers.get("set-cookie").split(";")[0];
    const base = new URL(s.url).origin;
    const post = (body) =>
      fetch(`${base}/api/reports/generate`, {
        method: "POST",
        headers: { cookie, "content-type": "application/json", "x-pulse-local": "1", origin: base },
        body: JSON.stringify({ formats: ["html"], source: "cli", path: folder, ...body }),
      });
    const ran = async () => {
      for (let i = 0; i < 60; i++) {
        await new Promise((r) => setTimeout(r, 50));
        const list = await (await fetch(`${base}/api/reports/generated`, { headers: { cookie } })).json();
        if (list.job && !list.job.running) return list.reports[0].id;
      }
      throw new Error("report did not finish");
    };
    const tokenSeen = async (id) =>
      JSON.parse(await readFile(join(tmpdir(), "snyk-pulse-reports", "reports", id, "seen.json"), "utf8")).token;
    assert.equal((await post({})).status, 202);
    assert.equal(await tokenSeen(await ran()), null, "saved token must not reach a CLI scan");
    assert.equal((await post({ token: "typed-token-123456" })).status, 202);
    assert.equal(await tokenSeen(await ran()), "typed-token-123456", "a token typed for the scan is used");
  } finally {
    await s.close?.();
  }
});
