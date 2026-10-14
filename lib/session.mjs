import { DEFAULT_SLA, day, normalizeIssues, shiftDay } from "./csv.mjs";
import { calculate, validatePolicy } from "./metrics.mjs";
import {
  computeExtensions,
  datasetRegistry,
  validateMetrics,
} from "./extensions.mjs";

export function createSession({
  datasets = [],
  metrics = [],
  policy = DEFAULT_SLA,
} = {}) {
  const registry = datasetRegistry(datasets),
    definitions = validateMetrics(metrics, registry);
  return {
    registry,
    definitions,
    policy: validatePolicy(policy),
    datasets: new Map(),
    snapshot: null,
    revision: 0,
    job: null,
    controller: null,
  };
}

export function addDatasets(
  session,
  incoming,
  { asOf = day(), source = "CSV import" } = {},
) {
  // Normalize everything before replacing live state: a failed API pull/import is atomic.
  const next = new Map(session.datasets);
  let snapshot = session.snapshot;
  for (const [name, data] of incoming) {
    if (!Object.hasOwn(session.registry, name))
      throw new Error("Dataset is not registered.");
    if (name === "issues") {
      const normalized = data.headers.length
        ? normalizeIssues(data, asOf)
        : {
            issues: [],
            excluded_deleted: 0,
            duplicates: 0,
            warnings: [
              "Snyk reported no export files for the selected scope and date filter.",
            ],
          };
      if (data.from && data.from > "1970-01-01T00:00:00.000Z")
        normalized.warnings.push(
          `API export begins at ${data.from}; backlog only covers the exported population.`,
        );
      snapshot = {
        id: session.revision + 1,
        source,
        as_of: asOf,
        imported_at: new Date().toISOString(),
        ...normalized,
      };
      next.set(name, { ...data, rows: normalized.issues.map((i) => i.raw) });
    } else next.set(name, data);
  }
  session.datasets = next;
  session.snapshot = snapshot;
  session.revision++;
}

/**
 * Fill group fields for issues whose export had no group columns, using an
 * org ID -> { id, name } mapping. Returns how many issues were updated.
 */
export function applyGroups(session, mapping = {}) {
  let updated = 0;
  for (const issue of session.snapshot?.issues || []) {
    const group = mapping[issue.org_id];
    if (!group || (issue.group_id && issue.group !== "Unknown group")) continue;
    issue.group = group.name;
    issue.group_id = group.id;
    updated++;
  }
  if (updated) session.revision++;
  return updated;
}

/** Load a stored version into the session, recomputing the snapshot as of its date. */
export function restoreVersion(session, version) {
  const incoming = new Map();
  for (const data of version.datasets) {
    // Datasets from a registry extension that is no longer loaded are skipped.
    if (!Object.hasOwn(session.registry, data.name)) continue;
    incoming.set(data.name, {
      headers: data.headers,
      rows: data.rows,
      source: data.source,
      ...(data.from ? { from: data.from } : {}),
    });
  }
  if (version.policy) session.policy = validatePolicy(version.policy);
  session.datasets = new Map();
  session.snapshot = null;
  if (incoming.size)
    addDatasets(session, incoming, {
      asOf: version.as_of,
      source: version.source,
    });
  session.version = version.id;
}

export function sessionState(session) {
  const snapshot = session.snapshot;
  const options = {};
  if (snapshot) {
    for (const field of ["group", "project_id", "product", "severity"])
      options[field] = [
        ...new Set(snapshot.issues.map((i) => i[field])),
      ].sort();
    options.org_id = [
      ...new Map(snapshot.issues.map((i) => [i.org_id, i.org])),
    ].map(([value, label]) => ({ value, label }));
  }
  const metadata = snapshot
    ? Object.fromEntries(
        Object.entries(snapshot).filter(([key]) => key !== "issues"),
      )
    : null;
  return {
    snapshot: metadata,
    count: snapshot?.issues.length || 0,
    policy: session.policy,
    options,
    registry: Object.values(session.registry),
    datasets: [...session.datasets].map(([name, data]) => ({
      name,
      rows: data.rows.length,
      headers: data.headers,
      source: data.source || "CSV import",
    })),
    definitions: session.definitions,
    job: session.job,
    version: session.version ?? null,
    mode: "utility",
  };
}

export function dashboard(session, query = {}) {
  const result = calculate(session.snapshot, session.policy, query);
  result.custom_metrics = computeExtensions(
    session.definitions,
    session.datasets,
    { ...result.period, filters: result.filters },
  );
  return result;
}

export function extensions(session, query = {}) {
  const end = query.end || session.snapshot?.as_of || day(),
    start = query.start || shiftDay(end, -89);
  const filters = Object.fromEntries(
    ["group", "org_id", "project_id", "product", "severity"].map((k) => [
      k,
      query[k] || "",
    ]),
  );
  return computeExtensions(session.definitions, session.datasets, {
    start,
    end,
    filters,
  });
}

export function demoDataset(asOf = day()) {
  let seed = 73;
  const random = () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed / 4294967296;
  };
  const rows = [];
  for (let n = 0; n < 540; n++) {
    const team = n % 4,
      days = Math.floor(random() * 250),
      introduced = shiftDay(asOf, -days),
      p = random(),
      status = p < 0.55 ? "Open" : p < 0.95 ? "Resolved" : "Ignored";
    const resolved = shiftDay(
        introduced,
        Math.floor(random() * (Math.min(days, 100) + 1)),
      ),
      s = random();
    rows.push({
      ASSET_FINDING_ID: `demo-${n}`,
      PROBLEM_ID: `DEMO-VULN-${n % 35}`,
      PROBLEM_TITLE: [
        "Improper input validation",
        "Prototype pollution",
        "Path traversal",
        "Out-of-bounds read",
        "Uncontrolled resource consumption",
      ][n % 5],
      GROUP_DISPLAY_NAME: "Acme · Demo",
      ORG_PUBLIC_ID: `demo-org-${team}`,
      ORG_DISPLAY_NAME: [
        "Platform",
        "Digital commerce",
        "Data & analytics",
        "Customer experience",
      ][team],
      PROJECT_PUBLIC_ID: `demo-project-${n % 24}`,
      PROJECT_NAME: `${["gateway", "checkout", "pipeline", "portal"][team]}/${n % 24}`,
      PRODUCT_NAME: [
        "Snyk Open Source",
        "Snyk Code",
        "Snyk Container",
        "Snyk IaC",
      ][Math.floor(n / 4) % 4],
      ISSUE_SEVERITY:
        s < 0.1 ? "Critical" : s < 0.42 ? "High" : s < 0.82 ? "Medium" : "Low",
      ISSUE_STATUS: status,
      FIRST_INTRODUCED: introduced,
      LAST_INTRODUCED: introduced,
      LAST_RESOLVED: status === "Resolved" ? resolved : "",
      LAST_IGNORED: status === "Ignored" ? resolved : "",
      COMPUTED_FIXABILITY: n % 3 ? "Fixable" : "Not fixable",
      EXPLOIT_MATURITY: n % 9 ? "No known exploit" : "Mature",
      REACHABILITY: n % 5 ? "Not reachable" : "Reachable",
      HAS_JIRA_ISSUE_ASSIGNED: String(n % 3 === 0),
      FIXED_IN_VERSION: n % 3 ? "2.4.1" : "",
      PACKAGE_NAME_AND_VERSION: `demo-package-${n % 10}@1.0.0`,
      INTRODUCTION_CATEGORY: [
        "New code",
        "New dependency",
        "Newly disclosed vulnerability",
      ][n % 3],
      ISSUE_DELETED_AT: "",
      PROJECT_DELETED_AT: "",
    });
  }
  return { headers: Object.keys(rows[0]), rows, source: "Synthetic demo" };
}
