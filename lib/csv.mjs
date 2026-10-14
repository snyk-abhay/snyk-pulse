import { createHash } from "node:crypto";

export const MAX_BYTES = 50 * 1024 * 1024;
export const MAX_ROWS = 100_000;
export const SEVERITIES = ["critical", "high", "medium", "low"];
export const DEFAULT_SLA = Object.freeze({
  critical: 15,
  high: 30,
  medium: 90,
  low: 180,
});
const nulls = new Set(["", "null", "none", "n/a"]);
export const value = (v) =>
  nulls.has(
    String(v ?? "")
      .trim()
      .toLowerCase(),
  )
    ? ""
    : String(v).trim();
export const day = () => new Date().toISOString().slice(0, 10);
export const daysBetween = (a, b) =>
  (Date.parse(b.slice(0, 10)) - Date.parse(a.slice(0, 10))) / 86400000;
export const shiftDay = (date, days) =>
  new Date(Date.parse(date) + days * 86400000).toISOString().slice(0, 10);

export function validDay(input) {
  if (
    typeof input !== "string" ||
    !/^\d{4}-\d{2}-\d{2}$/.test(input) ||
    !Number.isFinite(Date.parse(input)) ||
    new Date(input).toISOString().slice(0, 10) !== input ||
    input < "1970-01-01"
  )
    throw new Error("Use a valid date in YYYY-MM-DD format (1970 or later).");
  return input;
}

export function parseCSV(input) {
  if (Buffer.byteLength(input) > MAX_BYTES)
    throw new Error("CSV exceeds the 50 MiB utility limit.");
  let text;
  try {
    text =
      typeof input === "string"
        ? input
        : new TextDecoder("utf-8", { fatal: true }).decode(input);
  } catch {
    throw new Error("CSV must be UTF-8.");
  }
  text = text.replace(/^\uFEFF/, "");
  if (text.includes("\0")) throw new Error("CSV contains null bytes.");
  const records = [];
  let row = [],
    field = "",
    quoted = false,
    closed = false;
  function endField() {
    row.push(field);
    field = "";
    closed = false;
  }
  function endRow() {
    endField();
    if (row.some((v) => v !== "")) records.push(row);
    row = [];
    if (records.length > MAX_ROWS + 1)
      throw new Error("CSV exceeds 100,000 rows.");
  }
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') {
        quoted = false;
        closed = true;
      } else field += c;
    } else if (c === ",") endField();
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      endRow();
    } else if (c === '"' && !field && !closed) quoted = true;
    else if (closed || c === '"')
      throw new Error(
        `Malformed quoting near CSV record ${records.length + 1}.`,
      );
    else field += c;
  }
  if (quoted) throw new Error("CSV has an unterminated quoted field.");
  if (field || row.length || closed) endRow();
  if (!records.length) throw new Error("CSV has no header.");
  const headers = records
    .shift()
    .map((h) => h.trim().toUpperCase().replace(/\s+/g, "_"));
  if (headers.some((h) => !h) || new Set(headers).size !== headers.length)
    throw new Error("CSV headers must be nonempty and unique.");
  const rows = records.map((fields, index) => {
    if (fields.length !== headers.length)
      throw new Error(
        `CSV record ${index + 2}: column count differs from the header.`,
      );
    return Object.fromEntries(headers.map((h, i) => [h, fields[i]]));
  });
  return { headers, rows };
}

export function timestamp(raw, field = "Date") {
  if (!raw) return null;
  if (!/^\d{4}-\d{2}-\d{2}(?:$|[ T])/.test(raw))
    throw new Error(`${field} must be an ISO date/timestamp.`);
  validDay(raw.slice(0, 10));
  const input = /^\d{4}-\d{2}-\d{2}$/.test(raw)
    ? `${raw}T00:00:00Z`
    : raw.replace(" ", "T") + (/(Z|[+-]\d{2}:?\d{2})$/i.test(raw) ? "" : "Z");
  const ms = Date.parse(input);
  if (!Number.isFinite(ms))
    throw new Error(`${field} must be an ISO date/timestamp.`);
  return new Date(ms).toISOString();
}

function bool(raw) {
  return /^(true|yes|1)$/i.test(raw)
    ? true
    : /^(false|no|0)$/i.test(raw)
      ? false
      : null;
}
// Snyk exports some multi-value columns as JSON arrays, e.g. ["1.2.3","1.3.0"].
function listText(text) {
  if (!text.startsWith("[")) return text;
  try {
    const items = JSON.parse(text);
    if (Array.isArray(items)) return items.map(String).filter(Boolean).join(", ");
  } catch {}
  return text;
}

export function normalizeIssues(dataset, asOf = day()) {
  validDay(asOf);
  if (asOf > day()) throw new Error("Snapshot date cannot be in the future.");
  const required = [
    "PROBLEM_ID",
    "ORG_PUBLIC_ID",
    "ISSUE_SEVERITY",
    "ISSUE_STATUS",
    "FIRST_INTRODUCED",
  ];
  const missing = required.filter((k) => !dataset.headers.includes(k));
  if (missing.length)
    throw new Error(`Missing required issue columns: ${missing.join(", ")}.`);
  const seen = new Map(),
    issues = [];
  let excluded_deleted = 0,
    duplicates = 0;
  for (const [index, raw] of dataset.rows.entries()) {
    const get = (k) => value(raw[k]);
    if (
      ["ISSUE_DELETED_AT", "PROJECT_DELETED_AT", "GROUP_DELETED_AT"].some(get)
    ) {
      excluded_deleted++;
      continue;
    }
    try {
      if (required.some((k) => !get(k)))
        throw new Error("Required issue fields must not be empty.");
      const severity = get("ISSUE_SEVERITY").toLowerCase(),
        status = get("ISSUE_STATUS").toLowerCase();
      if (!SEVERITIES.includes(severity))
        throw new Error("Severity must be Critical, High, Medium or Low.");
      if (!["open", "resolved", "ignored"].includes(status))
        throw new Error("Status must be Open, Resolved or Ignored.");
      const finding = get("ASSET_FINDING_ID") || get("ISSUE_URL"),
        project = get("PROJECT_PUBLIC_ID");
      if (!finding && !project)
        throw new Error(
          "Include PROJECT_PUBLIC_ID, ASSET_FINDING_ID or ISSUE_URL for stable identity.",
        );
      const introduced = timestamp(get("FIRST_INTRODUCED"), "FIRST_INTRODUCED");
      const resolved = timestamp(get("LAST_RESOLVED"), "LAST_RESOLVED");
      const last_introduced = timestamp(
        get("LAST_INTRODUCED"),
        "LAST_INTRODUCED",
      );
      const ignored = timestamp(get("LAST_IGNORED"), "LAST_IGNORED");
      if (status === "resolved" && !resolved)
        throw new Error("Resolved issues require LAST_RESOLVED.");
      if (status === "ignored" && !ignored)
        throw new Error("Ignored issues require LAST_IGNORED.");
      for (const dt of [introduced, resolved, last_introduced, ignored].filter(
        Boolean,
      )) {
        if (dt.slice(0, 10) > asOf)
          throw new Error("Lifecycle date exceeds the snapshot date.");
        if (dt < introduced)
          throw new Error("Lifecycle date precedes FIRST_INTRODUCED.");
      }
      const identity = finding
        ? [get("ORG_PUBLIC_ID"), project, finding]
        : [
            get("ORG_PUBLIC_ID"),
            project,
            ...[
              "PROBLEM_ID",
              "PRODUCT_NAME",
              "PACKAGE_NAME_AND_VERSION",
              "FILE_PATH",
              "CODE_REGION",
              "PROJECT_TARGET_REF",
            ].map(get),
          ];
      const key = createHash("sha256")
        .update(JSON.stringify(identity))
        .digest("hex");
      const fingerprint = createHash("sha256")
        .update(JSON.stringify(raw))
        .digest("hex");
      if (seen.has(key)) {
        if (seen.get(key) !== fingerprint)
          throw new Error(
            "Conflicting finding identity. Include ASSET_FINDING_ID or ISSUE_URL.",
          );
        duplicates++;
        continue;
      }
      seen.set(key, fingerprint);
      const fix = get("COMPUTED_FIXABILITY").toLowerCase(),
        fixed = bool(get("FIXED_IN_AVAILABLE"));
      const exploit = get("EXPLOIT_MATURITY").toLowerCase(),
        reach = get("REACHABILITY").toLowerCase();
      issues.push({
        key,
        problem_id: get("PROBLEM_ID"),
        title: get("PROBLEM_TITLE") || get("PROBLEM_ID"),
        group:
          get("GROUP_DISPLAY_NAME") ||
          get("GROUP_PUBLIC_ID") ||
          "Unknown group",
        group_id: get("GROUP_PUBLIC_ID"),
        org_id: get("ORG_PUBLIC_ID"),
        org: get("ORG_DISPLAY_NAME") || get("ORG_NAME") || get("ORG_PUBLIC_ID"),
        project_id: project,
        project: get("PROJECT_NAME") || project || "Unknown project",
        product: get("PRODUCT_NAME") || "Unknown",
        // Repository/target and branch; Snyk names the target differently per export.
        target:
          get("PROJECT_TARGET") ||
          get("PROJECT_TARGET_DISPLAY_NAME") ||
          get("ASSET_NAME") ||
          "",
        target_ref: get("PROJECT_TARGET_REFERENCE") || get("PROJECT_TARGET_REF"),
        issue_type: get("ISSUE_TYPE") || "",
        severity,
        status,
        introduced,
        resolved,
        ignored,
        last_introduced,
        // Snyk exports use several spellings; unknown values stay null (no data).
        fixable:
          ["fixable", "partially fixable", "partially_fixable"].includes(fix) ||
          fixed === true
            ? true
            : [
                  "not fixable",
                  "not_fixable",
                  "unfixable",
                  "no fix supported",
                  "no fix available",
                  "not applicable",
                ].includes(fix) || fixed === false
              ? false
              : null,
        exploitable: [
          "mature",
          "poc",
          "proof of concept",
          "proof-of-concept",
        ].includes(exploit)
          ? true
          : [
                "no known exploit",
                "unproven",
                "not defined",
                "no data",
                "not applicable",
              ].includes(exploit)
            ? false
            : null,
        reachable:
          reach === "reachable"
            ? true
            : [
                  "not reachable",
                  "not_reachable",
                  "unreachable",
                  "no path found",
                  "not applicable",
                ].includes(reach)
              ? false
              : null,
        exploit_maturity: /^(no data|not applicable|)$/i.test(get("EXPLOIT_MATURITY"))
          ? "No data"
          : get("EXPLOIT_MATURITY"),
        kev: bool(get("IS_CISA_KEV")),
        priority: Number(get("PRIORITY_SCORE")) || null,
        project_type: get("PROJECT_TYPE") || "",
        jira: bool(get("HAS_JIRA_ISSUE_ASSIGNED")),
        fix_version: listText(get("FIXED_IN_VERSION")),
        package: get("PACKAGE_NAME_AND_VERSION"),
        cve: listText(get("CVE")),
        cwe: listText(get("CWE")),
        source: get("INTRODUCTION_CATEGORY") || "Unknown",
        raw,
      });
    } catch (error) {
      throw new Error(`CSV record ${index + 2}: ${error.message}`);
    }
  }
  const warnings = [];
  if (
    !["ISSUE_DELETED_AT", "PROJECT_DELETED_AT"].every((k) =>
      dataset.headers.includes(k),
    )
  )
    warnings.push(
      "Deletion columns are missing; deleted-row exclusion cannot be fully verified.",
    );
  return { issues, excluded_deleted, duplicates, warnings };
}

export function encodeCSV(headers, rows) {
  const cell = (v) => {
    let s = v == null ? "" : String(v);
    if (/^[\t\r\n]/.test(s) || /^[\s]*[=+\-@]/.test(s)) s = "'" + s;
    return /[",\r\n]/.test(s) ? '"' + s.replaceAll('"', '""') + '"' : s;
  };
  return (
    [headers, ...rows].map((row) => row.map(cell).join(",")).join("\r\n") +
    "\r\n"
  );
}
