import { setTimeout as delay } from "node:timers/promises";
import { gunzipSync } from "node:zlib";
import { MAX_BYTES, MAX_ROWS, parseCSV, timestamp } from "./csv.mjs";
import { BUILTIN_DATASETS } from "./extensions.mjs";
import { credentials, API_VERSION } from "./connection.mjs";
import { networkFailure } from "./network.mjs";
export { REGIONS, API_VERSION } from "./connection.mjs";

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function validateConnection(options, registry = BUILTIN_DATASETS) {
  const config = credentials(options);
  const scope = options.group ? "groups" : "orgs",
    id = options.group || options.org;
  if (options.group && options.org)
    throw new Error("Choose either an org or a group.");
  if (!uuid.test(id || ""))
    throw new Error("Provide a valid org or group UUID.");
  const datasets = options.datasets || ["issues"];
  if (
    !Array.isArray(datasets) ||
    !datasets.length ||
    datasets.length > 20 ||
    new Set(datasets).size !== datasets.length ||
    datasets.some((d) => !Object.hasOwn(registry, d))
  )
    throw new Error("Choose distinct registered dataset names (up to 20).");
  const from = timestamp(options.from || "1970-01-01T00:00:00Z", "Export from");
  if (
    options.exportId &&
    (!uuid.test(options.exportId) || datasets.length !== 1)
  )
    throw new Error("Resuming needs one dataset and a valid export UUID.");
  return {
    ...config,
    scope,
    id,
    datasets,
    from: new Date(from).toISOString(),
    exportId: options.exportId,
  };
}

export function exportBody(dataset, from, registry = BUILTIN_DATASETS) {
  const definition = registry[dataset];
  if (!definition) throw new Error("Unregistered dataset.");
  return {
    data: {
      type: "resource",
      attributes: {
        formats: ["csv"],
        dataset,
        filters: { [definition.dateFilter]: { from } },
      },
    },
  };
}

export function safeDownloadUrl(raw) {
  const url = new URL(raw);
  const h = url.hostname.toLowerCase();
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    (url.port && url.port !== "443") ||
    !(
      h.endsWith(".amazonaws.com") ||
      h === "storage.googleapis.com" ||
      h.endsWith(".storage.googleapis.com")
    )
  )
    throw new Error("Export returned an untrusted download host.");
  return url;
}

async function boundedBody(response, limit = MAX_BYTES) {
  if (Number(response.headers.get("content-length")) > limit) {
    await response.body?.cancel().catch(() => {});
    throw Object.assign(new Error("Export exceeds the utility size limit."), {
      code: "PULSE_SIZE_LIMIT",
      nonResumable: true,
    });
  }
  const reader = response.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > limit)
        throw Object.assign(
          new Error("Export exceeds the utility size limit."),
          { code: "PULSE_SIZE_LIMIT", nonResumable: true },
        );
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks);
}

export async function pullDatasets(
  options,
  {
    registry = BUILTIN_DATASETS,
    fetchImpl = fetch,
    sleep = delay,
    onProgress = () => {},
    signal,
    timeoutMs = 30 * 60_000,
    checkpoint = { exports: new Map(), completed: new Map() },
  } = {},
) {
  const config = validateConnection(options, registry);
  const deadlineSignal = AbortSignal.timeout(timeoutMs);
  const overall = signal
    ? AbortSignal.any([signal, deadlineSignal])
    : deadlineSignal;
  const requestSignal = () =>
    AbortSignal.any([overall, AbortSignal.timeout(60_000)]);
  let activeDataset, activeExportId;
  const progress = (data) =>
    onProgress({ dataset: activeDataset, exportId: activeExportId, ...data });
  const submissionUncertain = (error, method) => {
    if (method === "POST") {
      error.submissionUncertain = true;
      error.message +=
        " The submission outcome is unknown; Pulse did not send another export request. Check the original request before starting a new export.";
    }
    return error;
  };
  async function pause(ms, operation) {
    try {
      await sleep(ms, undefined, { signal: overall });
    } catch (error) {
      throw networkFailure(error, operation, overall);
    }
  }
  async function retry(attempt, failure, operation, retryAfter) {
    if (overall.aborted)
      throw networkFailure(overall.reason, operation, overall);
    const headerDelay =
      Number(retryAfter) || (Date.parse(retryAfter) - Date.now()) / 1000;
    const seconds = Math.min(Math.max(headerDelay || 2 ** attempt, 1), 120);
    progress({
      stage: "retry",
      code: failure.code,
      message:
        operation +
        ": connection interrupted or server busy. Retrying read " +
        (attempt + 1) +
        "/3 in " +
        seconds +
        "s; the existing export is retained.",
    });
    await pause(seconds * 1000, operation);
  }
  async function remote(
    url,
    { method = "GET", headers, body, redirect = "error", operation, limit },
  ) {
    for (let attempt = 0; attempt < 4; attempt++) {
      if (overall.aborted)
        throw networkFailure(overall.reason, operation, overall);
      let response;
      try {
        response = await fetchImpl(url, {
          method,
          headers,
          redirect,
          signal: requestSignal(),
          ...(body ? { body: JSON.stringify(body) } : {}),
        });
      } catch (error) {
        const failure = networkFailure(error, operation, overall);
        if (
          method === "GET" &&
          failure.retryable &&
          attempt < 3 &&
          !overall.aborted
        ) {
          await retry(attempt, failure, operation);
          continue;
        }
        throw submissionUncertain(failure, method);
      }
      if (
        method === "GET" &&
        ([408, 425, 429].includes(response.status) || response.status >= 500)
      ) {
        const retryAfter = response.headers.get("retry-after");
        await response.body?.cancel().catch(() => {});
        const failure = Object.assign(
          new Error(
            operation +
              ": Snyk is temporarily unavailable (HTTP " +
              response.status +
              "). Resume the existing export later.",
          ),
          { code: "HTTP_" + response.status },
        );
        if (attempt === 3) throw failure;
        await retry(attempt, failure, operation, retryAfter);
        continue;
      }
      if (!response.ok) {
        await response.body?.cancel().catch(() => {});
        return { response, bytes: null };
      }
      try {
        return { response, bytes: await boundedBody(response, limit) };
      } catch (error) {
        const failure =
          error.code === "PULSE_SIZE_LIMIT"
            ? error
            : networkFailure(error, operation, overall);
        if (
          method === "GET" &&
          failure.retryable &&
          attempt < 3 &&
          !overall.aborted
        ) {
          await retry(attempt, failure, operation);
          continue;
        }
        throw submissionUncertain(failure, method);
      }
    }
  }
  async function api(method, path, body) {
    const operation =
      method === "POST"
        ? "Submitting " + activeDataset + " export"
        : path.startsWith("/jobs/")
          ? "Checking " + activeDataset + " export status"
          : "Retrieving " + activeDataset + " download links";
    const prefix = "/rest/" + config.scope + "/" + config.id;
    const originalPath = prefix + path;
    let requestPath = originalPath;
    let response, bytes;
    for (let hop = 0; hop < 4; hop++) {
      ({ response, bytes } = await remote(
        config.base + requestPath + "?version=" + API_VERSION,
        {
          method,
          body,
          // Inspect redirects instead of letting fetch turn them into an opaque
          // network error or forward the token to a destination from a response.
          redirect: "manual",
          operation,
          limit: 4 * 1024 * 1024,
          headers: {
            Authorization: config.authScheme + " " + config.token,
            Accept: "application/vnd.api+json",
            "Content-Type": "application/vnd.api+json",
          },
        },
      ));
      if (![301, 302, 303, 307, 308].includes(response.status)) break;
      let target;
      try {
        target = new URL(
          response.headers.get("location"),
          config.base + requestPath,
        );
      } catch {}
      const trusted =
        target &&
        target.origin === config.base &&
        !target.username &&
        !target.password;
      const resultPath = path.startsWith("/jobs/export/")
        ? prefix + path.slice(5)
        : null;
      if (
        method === "GET" &&
        trusted &&
        resultPath &&
        target.pathname.replace(/\/$/, "") === resultPath
      ) {
        // The status endpoint points to this exact export's result resource.
        // Read the canonical result URL next; never use a returned host/query.
        return { data: { attributes: { status: "FINISHED" } } };
      }
      if (
        method === "GET" &&
        trusted &&
        target.pathname.replace(/\/$/, "") === originalPath &&
        hop < 3
      ) {
        requestPath = target.pathname;
        continue;
      }
      throw submissionUncertain(
        Object.assign(
          new Error(
            operation +
              ": Snyk returned an unexpected redirect (HTTP " +
              response.status +
              "). Pulse did not forward your token to that destination. Check the selected Snyk region and any proxy or sign-in gateway.",
          ),
          { code: "HTTP_REDIRECT", retryable: false },
        ),
        method,
      );
    }
    if (!response.ok) {
      const failure = Object.assign(
        new Error(
          response.status === 401
            ? "Snyk authentication failed. Validate your token again in the same region."
            : response.status === 403
              ? "This token cannot export the selected scope/dataset. Check permissions and plan entitlement."
              : response.status === 429
                ? "Snyk export submission is rate limited (20 POSTs/hour). Retry later; Pulse did not repeat the submission."
                : operation + " failed (HTTP " + response.status + ").",
        ),
        { code: "HTTP_" + response.status },
      );
      throw response.status >= 500 || response.status === 408
        ? submissionUncertain(failure, method)
        : failure;
    }
    try {
      return JSON.parse(bytes.toString("utf8"));
    } catch {
      throw submissionUncertain(
        new Error(
          "Snyk returned an invalid export response while " +
            operation.toLowerCase() +
            ".",
        ),
        method,
      );
    }
  }
  async function download(raw) {
    let url = safeDownloadUrl(raw);
    for (let hop = 0; hop < 4; hop++) {
      const { response, bytes } = await remote(url, {
        redirect: "manual",
        operation: "Downloading " + activeDataset + " export file",
        limit: MAX_BYTES,
      });
      if (response.status >= 300 && response.status < 400) {
        url = safeDownloadUrl(
          new URL(response.headers.get("location") || "", url),
        );
        continue;
      }
      if (!response.ok)
        throw Object.assign(
          new Error(
            "Export file download failed (HTTP " + response.status + ").",
          ),
          {
            code: "DOWNLOAD_HTTP_" + response.status,
            refreshDownload: [401, 403, 404, 410].includes(response.status),
          },
        );
      try {
        const decoded =
          bytes[0] === 0x1f && bytes[1] === 0x8b
            ? gunzipSync(bytes, { maxOutputLength: MAX_BYTES })
            : bytes;
        return { ...parseCSV(decoded), byteLength: decoded.length };
      } catch (error) {
        error.nonResumable = true;
        throw error;
      }
    }
    throw new Error("Export download redirected too many times.");
  }
  const outputs = checkpoint.completed;
  for (const dataset of config.datasets) {
    activeDataset = dataset;
    activeExportId = checkpoint.exports.get(dataset) || config.exportId;
    if (outputs.has(dataset)) continue;
    progress({
      dataset,
      stage: "starting",
      message: `${activeExportId ? "Resuming" : "Starting"} ${dataset} export.`,
    });
    const id =
      activeExportId ||
      (await api("POST", "/export", exportBody(dataset, config.from, registry)))
        ?.data?.id;
    if (!uuid.test(id || ""))
      throw submissionUncertain(
        new Error("Snyk did not return a valid export ID."),
        "POST",
      );
    activeExportId = id;
    checkpoint.exports.set(dataset, id);
    progress({
      stage: "pending",
      message: dataset + ": export accepted; checking status.",
    });
    let status = "";
    for (let attempt = 0; ; attempt++) {
      if (overall.aborted)
        throw networkFailure(
          overall.reason,
          "Checking " + dataset + " export status",
          overall,
        );
      const result = await api("GET", `/jobs/export/${id}`);
      status = String(result?.data?.attributes?.status || "").toUpperCase();
      progress({
        dataset,
        exportId: id,
        stage: status.toLowerCase(),
        message: `${dataset}: ${status.toLowerCase()}`,
      });
      if (status === "FINISHED") break;
      if (status === "ERROR")
        throw Object.assign(
          new Error(
            `Snyk export ${id} failed on the server. Start a new export after checking the dataset and scope.`,
          ),
          { terminalExport: true },
        );
      if (!["PENDING", "STARTED"].includes(status))
        throw new Error("Snyk returned an unknown export status.");
      await pause(
        Math.min(5 + attempt * 5, 30) * 1000,
        "Waiting for " + dataset + " export",
      );
    }
    const results = async () => {
      const body = await api("GET", `/export/${id}`);
      const parts = body?.data?.attributes?.results;
      if (
        !Array.isArray(parts) ||
        parts.some((p) => typeof p?.url !== "string")
      )
        throw new Error("Snyk returned invalid export results.");
      return parts.map((p) => p.url);
    };
    let urls = await results(),
      headers = null,
      totalBytes = 0;
    const rows = [];
    for (let index = 0; index < urls.length; index++) {
      let parsed;
      try {
        parsed = await download(urls[index]);
      } catch (error) {
        if (!error.refreshDownload || overall.aborted) throw error;
        progress({
          stage: "refreshing",
          message: dataset + ": refreshing expired download links.",
        });
        urls = await results();
        if (!urls[index])
          throw new Error(
            "Export parts changed while downloading; retry the existing export.",
          );
        parsed = await download(urls[index]);
      }
      if (headers && JSON.stringify(headers) !== JSON.stringify(parsed.headers))
        throw Object.assign(
          new Error("Export parts have different column schemas."),
          { nonResumable: true },
        );
      totalBytes += parsed.byteLength;
      if (totalBytes > MAX_BYTES)
        throw Object.assign(new Error("Combined dataset exceeds 50 MiB."), {
          nonResumable: true,
        });
      headers = parsed.headers;
      for (const row of parsed.rows) rows.push(row);
      if (rows.length > MAX_ROWS)
        throw Object.assign(new Error("Export exceeds 100,000 rows."), {
          nonResumable: true,
        });
      progress({
        dataset,
        exportId: id,
        stage: "downloading",
        message: `${dataset}: downloaded ${index + 1}/${urls.length} parts.`,
      });
    }
    outputs.set(dataset, {
      headers: headers || [],
      rows,
      source: "Snyk Export API",
      exportId: id,
      scope: { kind: config.scope, id: config.id, region: config.region },
      from: config.from,
    });
  }
  return outputs;
}
