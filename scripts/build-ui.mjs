import { cp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
const root = new URL("../", import.meta.url);
const result = spawnSync(
  process.platform === "win32" ? "npm.cmd" : "npm",
  ["run", "build"],
  { cwd: new URL("frontend/", root), stdio: "inherit" },
);
if (result.status !== 0) process.exit(result.status || 1);
await rm(new URL("web/", root), { recursive: true, force: true });
await mkdir(new URL("web/", root), { recursive: true });
await cp(new URL("frontend/dist/", root), new URL("web/", root), {
  recursive: true,
});
// The requested implementation entry is also available by its original design filename.
await writeFile(
  new URL("web/Snyk Pulse.dc.html", root),
  await readFile(new URL("web/index.html", root)),
);
console.log("Bundled dashboard ready. End users need only Node 22+.");
