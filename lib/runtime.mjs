import { randomBytes, createHash } from "node:crypto";
import {
  mkdir,
  lstat,
  chmod,
  readdir,
  readFile,
  writeFile,
  rename,
  rm,
  realpath,
} from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import { basename, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { setTimeout as delay } from "node:timers/promises";
import { createConnection } from "node:net";
import { startServer } from "./server.mjs";

export const DEFAULT_PORT = 8780;
const APP = "snyk-pulse-utility";
const userId = createHash("sha256")
  .update(userInfo().username)
  .digest("hex")
  .slice(0, 16);
const DIRECTORY = join(tmpdir(), `snyk-pulse-${userId}`);
const instancePattern = /^[a-f0-9]{32}$/;
const runFile = promisify(execFile);

async function resumeSuspended(record) {
  if (
    !["darwin", "linux"].includes(process.platform) ||
    record.pid === process.pid
  )
    return false;
  // A paused process cannot answer HTTP. Before SIGCONT, independently verify
  // ownership, its CLI entry point and the PID actually holding this port.
  // No termination signal is used; shutdown still requires the control token.
  const run = async (command, args) =>
    (
      await runFile(command, args, {
        encoding: "utf8",
        timeout: 2000,
        maxBuffer: 32 * 1024,
        env: { ...process.env, LC_ALL: "C" },
      })
    ).stdout.trim();
  try {
    const pid = String(record.pid);
    const infoArgs = ["-p", pid, "-o", "uid=,stat=,lstart="];
    const info = await run("ps", infoArgs);
    const match = /^(\d+)\s+(\S+)\s+(.+)$/.exec(info);
    if (
      !match ||
      Number(match[1]) !== process.getuid() ||
      !match[2].startsWith("T")
    )
      return false;
    const [command, location, listeners, cli] = await Promise.all([
      run("ps", ["-ww", "-p", pid, "-o", "args="]),
      run("lsof", ["-a", "-p", pid, "-d", "cwd", "-Fn"]),
      run("lsof", [
        "-a",
        "-p",
        pid,
        `-iTCP:${record.port}`,
        "-sTCP:LISTEN",
        "-Fp",
      ]),
      realpath(fileURLToPath(new URL("../pulse.mjs", import.meta.url))),
    ]);
    if (!listeners.split("\n").includes("p" + pid)) return false;
    const cwdLine = location.split("\n").find((line) => line.startsWith("n"));
    if (!cwdLine) return false;
    const cwd = await realpath(cwdLine.slice(1));
    const entry = relative(cwd, cli);
    const executables = new Set([
      "node",
      process.execPath,
      basename(process.execPath),
      process.argv0,
    ]);
    const entries = [cli, entry, "./" + entry];
    const isPulse = [...executables].some((executable) =>
      entries.some((script) => {
        const prefix = executable + " " + script;
        return command === prefix || command.startsWith(prefix + " ");
      }),
    );
    if (!isPulse || (await run("ps", infoArgs)) !== info) return false;
    process.kill(record.pid, "SIGCONT");
    return true;
  } catch {
    // Missing OS tools, an exited process or unverifiable metadata fails closed.
    // Never include process arguments in errors: they can contain API tokens.
    return false;
  }
}

async function privateDirectory(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (
    !info.isDirectory() ||
    info.isSymbolicLink() ||
    (process.getuid && info.uid !== process.getuid())
  )
    throw new Error(
      "Pulse runtime directory is not a private directory owned by this user.",
    );
  if (process.platform !== "win32") await chmod(directory, 0o700);
}

async function readRecord(file) {
  const info = await lstat(file);
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    info.size > 4096 ||
    (process.getuid && info.uid !== process.getuid())
  )
    throw new Error("Invalid Pulse runtime record.");
  const data = JSON.parse(await readFile(file, "utf8"));
  if (
    data.app !== APP ||
    !instancePattern.test(data.instanceId) ||
    !/^[a-f0-9]{64}$/.test(data.controlToken) ||
    !Number.isInteger(data.pid) ||
    data.pid < 1 ||
    !Number.isInteger(data.port) ||
    data.port < 1 ||
    data.port > 65535
  )
    throw new Error("Invalid Pulse runtime record.");
  return data;
}

function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code !== "ESRCH";
  }
}

async function health(port) {
  let response;
  try {
    response = await fetch(`http://127.0.0.1:${port}/api/health`, {
      redirect: "error",
      signal: AbortSignal.timeout(1500),
    });
    if (!response.ok) return null;
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body || []) {
      size += chunk.length;
      if (size > 4096) return null;
      chunks.push(chunk);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return null;
  } finally {
    if (response?.body && !response.body.locked)
      await response.body.cancel().catch(() => {});
  }
}

async function departed(record) {
  const listening = await new Promise((resolve) => {
    const socket = createConnection({ host: "127.0.0.1", port: record.port });
    const finish = (value) => {
      socket.destroy();
      resolve(value);
    };
    socket.setTimeout(500, () => finish(true));
    socket.once("connect", () => finish(true));
    socket.once("error", (error) => finish(error.code !== "ECONNREFUSED"));
  });
  if (!listening) return true;
  const current = await health(record.port);
  return !!current && current.instanceId !== record.instanceId;
}

export async function stopRunning({
  directory = DIRECTORY,
  log = () => {},
} = {}) {
  await privateDirectory(directory);
  const files = (await readdir(directory)).filter((name) =>
    /^[a-f0-9]{32}\.json$/.test(name),
  );
  let stopped = 0;
  for (const name of files) {
    const file = join(directory, name);
    let record;
    try {
      record = await readRecord(file);
    } catch (error) {
      if (error.code === "ENOENT") continue;
      throw new Error(
        "Pulse runtime metadata is invalid. No process was stopped.",
      );
    }
    if (!alive(record.pid)) {
      await rm(file, { force: true });
      continue;
    }
    let current = await health(record.port);
    if (!current && (await resumeSuspended(record))) {
      log(`Resumed suspended Pulse instance on port ${record.port}.`);
      current = await health(record.port);
    }
    if (!current) {
      if (await departed(record)) {
        await rm(file, { force: true });
        continue;
      }
      throw new Error(
        `Cannot verify the previous Pulse instance on port ${record.port}. Stop it in its terminal and retry. No unverified process was stopped.`,
      );
    }
    if (current.app !== APP || current.instanceId !== record.instanceId) {
      // A stale PID/port may now belong to an unrelated program. Never signal it.
      await rm(file, { force: true });
      continue;
    }
    let response;
    try {
      response = await fetch(
        `http://127.0.0.1:${record.port}/api/runtime/stop`,
        {
          method: "POST",
          redirect: "error",
          signal: AbortSignal.timeout(3000),
          headers: { "X-Pulse-Control": record.controlToken },
        },
      );
      if (response.status !== 202) throw new Error();
    } catch {
      // Another simultaneous launch may have already stopped this exact instance.
      if (!(await departed(record)))
        throw new Error(
          `Pulse on port ${record.port} did not accept a stop request. Stop it in its terminal and retry.`,
        );
    } finally {
      await response?.body?.cancel().catch(() => {});
    }
    let released = false;
    for (let attempt = 0; attempt < 8; attempt++) {
      if (await departed(record)) {
        released = true;
        break;
      }
      await delay(100);
    }
    if (!released)
      throw new Error(
        `Pulse on port ${record.port} is still shutting down. Retry in a moment.`,
      );
    await rm(file, { force: true });
    stopped++;
    log(`Stopped previous Pulse instance on port ${record.port}.`);
  }
  return stopped;
}

// Name the process holding a port (macOS/Linux) for the conflict message only.
async function portHolder(port) {
  if (!["darwin", "linux"].includes(process.platform)) return null;
  try {
    const { stdout } = await runFile(
      "lsof",
      ["-nP", `-iTCP:${port}`, "-sTCP:LISTEN", "-Fpc"],
      { encoding: "utf8", timeout: 2000, maxBuffer: 32 * 1024 },
    );
    const pid = /^p(\d+)/m.exec(stdout)?.[1],
      command = /^c(.+)$/m.exec(stdout)?.[1];
    return pid ? `${command || "process"}, PID ${pid}` : null;
  } catch {
    return null;
  }
}

export async function startManagedServer(
  session,
  options = {},
  { directory = DIRECTORY, log = () => {}, onStopped = () => {} } = {},
) {
  const port = options.port ?? DEFAULT_PORT;
  if (!Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error(
      "Choose a fixed port from 1 to 65535. Port 0 is not supported.",
    );
  await privateDirectory(directory);
  await stopRunning({ directory, log });
  const instanceId = randomBytes(16).toString("hex"),
    controlToken = randomBytes(32).toString("hex");
  const file = join(directory, `${instanceId}.json`),
    pending = `${file}.pending`;
  const cleanup = () => rm(file, { force: true });
  let running;
  try {
    running = await startServer(session, {
      ...options,
      port,
      control: { instanceId, token: controlToken },
      onStopped: async () => {
        await cleanup();
        await onStopped();
      },
    });
    // This private record contains process-control metadata only, never Snyk
    // credentials or dataset contents. Publish it only after the port is bound.
    await writeFile(
      pending,
      JSON.stringify({
        app: APP,
        instanceId,
        controlToken,
        pid: process.pid,
        port,
      }),
      { mode: 0o600, flag: "wx" },
    );
    await rename(pending, file);
    running.server.once("close", () => {
      void cleanup().catch(() => {});
    });
    return {
      ...running,
      close: async () => {
        await running.close();
        await cleanup();
      },
    };
  } catch (error) {
    await running?.close();
    await rm(pending, { force: true });
    await cleanup();
    if (error.code === "EADDRINUSE") {
      const holder = await portHolder(port);
      throw new Error(
        `Port ${port} is used by another application${holder ? ` (${holder})` : ""}, not Pulse, so Pulse left it running. ` +
          `Start Pulse on a free port once with --port, e.g. node pulse.mjs --port ${port + 1}; Pulse remembers it for next time.`,
      );
    }
    throw error;
  }
}
