// Copy the Snyk report generator into Pulse as one self-contained file.
// Source: ../snyk_report (unchanged). Output: vendor/snyk-auto-report.mjs,
// bundled with esbuild so it runs on any Node 22 without TypeScript support.
// Re-run after changing snyk_report: npm run vendor:report
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = new URL("../", import.meta.url);
const source = fileURLToPath(new URL("../snyk_report/snyk-auto-report.mts", root));
const esbuild = fileURLToPath(new URL("../node_modules/.bin/esbuild", root));
const out = new URL("vendor/snyk-auto-report.mjs", root);

if (!existsSync(source)) {
  console.error(`Report generator source not found: ${source}`);
  process.exit(1);
}
if (!existsSync(esbuild)) {
  console.error("esbuild not found. Run npm install in the snyk-scripts folder first.");
  process.exit(1);
}
await mkdir(new URL("vendor/", root), { recursive: true });
const built = spawnSync(
  esbuild,
  [
    source,
    "--bundle",
    "--platform=node",
    "--target=node22",
    "--format=esm",
    "--packages=external",
    "--legal-comments=none",
    `--outfile=${fileURLToPath(out)}`,
  ],
  { stdio: "inherit" },
);
if (built.status !== 0) process.exit(built.status || 1);

const bytes = await readFile(out);
const commit = spawnSync("git", ["log", "-1", "--format=%h", "--", "snyk_report"], {
  cwd: fileURLToPath(new URL("../", root)),
  encoding: "utf8",
}).stdout.trim();
const header =
  `// Vendored copy of snyk_report/snyk-auto-report.mts (generated; do not edit).\n` +
  `// Source commit ${commit || "unknown"} · sha256 ${createHash("sha256").update(bytes).digest("hex").slice(0, 16)}\n` +
  `// Refresh with: npm run vendor:report\n`;
// A "#!" line is only valid as the first line, so the header goes after it.
const body = bytes.toString("utf8");
const shebang = body.startsWith("#!") ? body.slice(0, body.indexOf("\n") + 1) : "";
await writeFile(out, shebang + header + body.slice(shebang.length));

// Check the final file (after the header) runs, so a broken copy is never left behind.
const check = spawnSync(process.execPath, [fileURLToPath(out), "--help"], {
  encoding: "utf8",
});
if (check.status !== 0 || !/snyk-auto-report/.test(check.stderr + check.stdout)) {
  console.error("The bundled report generator failed its --help check.");
  process.exit(1);
}
console.log(`Report generator copied to vendor/snyk-auto-report.mjs (${Math.round(bytes.length / 1024)} KB).`);
