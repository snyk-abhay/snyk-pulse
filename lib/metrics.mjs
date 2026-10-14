import {
  DEFAULT_SLA,
  SEVERITIES,
  daysBetween,
  shiftDay,
  validDay,
} from "./csv.mjs";
import { OWASP_TOP10, owaspCategories } from "./owasp.mjs";

const round = (v, digits = 2) => Math.round(v * 10 ** digits) / 10 ** digits;
const mean = (values) =>
  values.length
    ? round(values.reduce((a, b) => a + b, 0) / values.length)
    : null;
const inPeriod = (dt, start, end) =>
  !!dt && dt.slice(0, 10) >= start && dt.slice(0, 10) <= end;
// Count rows known to be true; unavailable only when no row carries the field.
const knownCount = (rows, field) =>
  !rows.length || rows.some((r) => r[field] != null)
    ? rows.filter((r) => r[field]).length
    : null;
const grouped = (rows, fn) => {
  const m = new Map();
  for (const r of rows) {
    const key = fn(r);
    m.set(key, (m.get(key) || 0) + 1);
  }
  return [...m]
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);
};
function percentile(values, q) {
  if (!values.length) return null;
  const v = [...values].sort((a, b) => a - b),
    p = (v.length - 1) * q,
    l = Math.floor(p);
  return round(v[l] + (v[Math.min(l + 1, v.length - 1)] - v[l]) * (p - l));
}
export function validatePolicy(policy) {
  if (!policy || Object.keys(policy).some((k) => !SEVERITIES.includes(k)))
    throw new Error("SLA accepts critical, high, medium and low only.");
  const result = { ...DEFAULT_SLA, ...policy };
  if (
    Object.values(result).some((v) => !Number.isInteger(v) || v < 1 || v > 3650)
  )
    throw new Error("SLA days must be integers from 1 to 3650.");
  return result;
}

export function calculate(snapshot, policy = DEFAULT_SLA, query = {}) {
  if (!snapshot)
    throw new Error("Import an issue CSV or pull the issues dataset first.");
  const end = validDay(query.end || snapshot.as_of),
    start = validDay(query.start || shiftDay(end, -89));
  if (end > snapshot.as_of || start > end || daysBetween(start, end) > 730)
    throw new Error("Select 1–731 days ending on or before the snapshot date.");
  const filters = Object.fromEntries(
    ["group", "org_id", "project_id", "product", "severity"].map((k) => [
      k,
      query[k] || "",
    ]),
  );
  if (filters.severity && !SEVERITIES.includes(filters.severity))
    throw new Error("Invalid severity.");
  const issues = snapshot.issues.filter((i) =>
    Object.entries(filters).every(([k, v]) => !v || i[k] === v),
  );
  const open = issues.filter((i) => i.status === "open"),
    introduced = issues.filter((i) => inPeriod(i.introduced, start, end));
  const fixed = issues.filter(
    (i) => i.status === "resolved" && inPeriod(i.resolved, start, end),
  );
  const ignored = issues.filter((i) => i.status === "ignored"),
    newlyIgnored = issues.filter((i) => inPeriod(i.ignored, start, end));
  const high = open.filter((i) => ["critical", "high"].includes(i.severity));
  const age = (i) => daysBetween(i.introduced, snapshot.as_of),
    duration = (i) =>
      (Date.parse(i.resolved) - Date.parse(i.introduced)) / 86400000;
  const times = fixed.map(duration),
    jira = knownCount(high, "jira");
  const metrics = {
    new: introduced.length,
    new_critical_high: introduced.filter((i) =>
      ["critical", "high"].includes(i.severity),
    ).length,
    reintroduced: issues.filter(
      (i) =>
        inPeriod(i.last_introduced, start, end) &&
        i.resolved &&
        i.last_introduced > i.resolved,
    ).length,
    fixed: fixed.length,
    fixed_critical_high: fixed.filter((i) =>
      ["critical", "high"].includes(i.severity),
    ).length,
    net_change: fixed.length - introduced.length,
    burn_down_ratio: introduced.length
      ? round(fixed.length / introduced.length)
      : null,
    open: open.length,
    open_critical_high: high.length,
    fixable_open: knownCount(open, "fixable"),
    exploitable_open: knownCount(open, "exploitable"),
    reachable_open: knownCount(open, "reachable"),
    mttr_days: mean(times),
    mttr_critical_days: mean(
      fixed.filter((i) => i.severity === "critical").map(duration),
    ),
    median_fix_days: percentile(times, 0.5),
    p90_fix_days: percentile(times, 0.9),
    mean_open_age_days: mean(open.map(age)),
    sla_compliance: fixed.length
      ? round(
          (fixed.filter(
            (i) => daysBetween(i.introduced, i.resolved) <= policy[i.severity],
          ).length /
            fixed.length) *
            100,
          1,
        )
      : null,
    over_sla: open.filter((i) => age(i) > policy[i.severity]).length,
    due_7_days: open.filter(
      (i) =>
        policy[i.severity] - age(i) >= 0 && policy[i.severity] - age(i) <= 7,
    ).length,
    ignored: ignored.length,
    critical_ignored: ignored.filter((i) => i.severity === "critical").length,
    ignore_rate:
      fixed.length + newlyIgnored.length
        ? round(
            (newlyIgnored.length / (fixed.length + newlyIgnored.length)) * 100,
            1,
          )
        : null,
    jira_linkage:
      high.length && jira != null ? round((jira / high.length) * 100, 1) : null,
    exploitable_reachable_open: open.filter((i) => i.exploitable && i.reachable)
      .length,
    mature_exploit_open: open.filter((i) =>
      /mature/i.test(i.exploit_maturity),
    ).length,
    kev_open: knownCount(open, "kev"),
    secrets_open: open.filter((i) => /secret/i.test(i.issue_type || i.product))
      .length,
    affected_repos: new Set(open.map((i) => i.target).filter(Boolean)).size,
    repos_over_sla: new Set(
      open
        .filter((i) => i.target && age(i) > policy[i.severity])
        .map((i) => i.target),
    ).size,
    fixable_critical_high: high.filter((i) => i.fixable).length,
    vulnerable_packages: new Set(open.map((i) => i.package).filter(Boolean))
      .size,
    fix_rate: null,
    risk_score: null,
    product_coverage: null,
    projects_monitored: null,
    stale_projects: null,
    scans_run: null,
    pr_pass_rate: null,
    issues_prevented: null,
    issue_density: null,
    new_per_project: null,
  };
  const previousStart = shiftDay(start, -(daysBetween(start, end) + 1)),
    previousEnd = shiftDay(start, -1);
  const prevNew = issues.filter((i) =>
      inPeriod(i.introduced, previousStart, previousEnd),
    ).length,
    prevFixed = issues.filter(
      (i) =>
        i.status === "resolved" &&
        inPeriod(i.resolved, previousStart, previousEnd),
    ).length;
  const trend = [];
  for (let d = start; d <= end; d = shiftDay(d, 7))
    trend.push({ date: d, introduced: 0, fixed: 0 });
  for (const [name, rows, field] of [
    ["introduced", introduced, "introduced"],
    ["fixed", fixed, "resolved"],
  ])
    for (const i of rows)
      trend[Math.floor(daysBetween(start, i[field]) / 7)][name]++;
  const ranks = new Map();
  for (const i of open) {
    const key = i.org_id;
    if (!ranks.has(key))
      ranks.set(key, {
        org_id: i.org_id,
        org: i.org,
        open: 0,
        over_sla: 0,
        critical_high: 0,
      });
    const r = ranks.get(key);
    r.open++;
    r.over_sla += Number(age(i) > policy[i.severity]);
    r.critical_high += Number(["critical", "high"].includes(i.severity));
  }
  const all = open
    .map(({ raw, ...i }) => ({
      ...i,
      age_days: age(i),
      sla_days: policy[i.severity],
      over_sla: age(i) > policy[i.severity],
      days_to_sla: policy[i.severity] - age(i),
    }))
    .sort(
      (a, b) =>
        a.days_to_sla - b.days_to_sla ||
        SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity),
    );
  const severity = grouped(open, (i) => i.severity),
    aging = grouped(open, (i) =>
      age(i) <= 30
        ? "0–30"
        : age(i) <= 90
          ? "31–90"
          : age(i) <= 180
            ? "91–180"
            : "181+",
    );
  const top = (rows, limit = 10) => rows.slice(0, limit);
  // Split JSON-list text ("CWE-79, CWE-89") so each identifier counts once per finding.
  const each = (rows, field) =>
    grouped(
      rows.flatMap((i) =>
        (i[field] || "")
          .split(", ")
          .filter(Boolean)
          .map((v) => ({ v })),
      ),
      (r) => r.v,
    );
  const sevRank = (rows) =>
    rows.filter((i) => ["critical", "high"].includes(i.severity)).length;
  const repoMap = new Map();
  for (const i of open) {
    const key = i.target || i.project || "Unknown";
    if (!repoMap.has(key))
      repoMap.set(key, {
        repo: key,
        org: i.org,
        open: 0,
        critical_high: 0,
        fixable: 0,
        over_sla: 0,
        projects: new Set(),
        branches: new Set(),
      });
    const r = repoMap.get(key);
    r.open++;
    r.critical_high += Number(["critical", "high"].includes(i.severity));
    r.fixable += Number(!!i.fixable);
    r.over_sla += Number(age(i) > policy[i.severity]);
    r.projects.add(i.project);
    if (i.target_ref) r.branches.add(i.target_ref);
  }
  const repositories = [...repoMap.values()]
    .map(({ projects, branches, ...r }) => ({
      ...r,
      projects: projects.size,
      branches: [...branches].sort(),
    }))
    .sort(
      (a, b) =>
        b.critical_high - a.critical_high ||
        b.over_sla - a.over_sla ||
        b.open - a.open,
    );
  const packageMap = new Map();
  for (const i of open.filter((x) => x.package)) {
    if (!packageMap.has(i.package))
      packageMap.set(i.package, {
        name: i.package,
        value: 0,
        critical_high: 0,
        fixable: 0,
        repos: new Set(),
        fix_version: i.fix_version,
      });
    const p = packageMap.get(i.package);
    p.value++;
    p.critical_high += Number(["critical", "high"].includes(i.severity));
    p.fixable += Number(!!i.fixable);
    if (i.target) p.repos.add(i.target);
    if (!p.fix_version && i.fix_version) p.fix_version = i.fix_version;
  }
  const packages = [...packageMap.values()]
    .map(({ repos, ...p }) => ({ ...p, repos: repos.size }))
    .sort((a, b) => b.critical_high - a.critical_high || b.value - a.value);
  const products = grouped(open, (i) => i.product).map((p) => {
    const rows = open.filter((i) => i.product === p.name);
    return {
      ...p,
      critical_high: sevRank(rows),
      over_sla: rows.filter((i) => age(i) > policy[i.severity]).length,
    };
  });
  // Every OWASP category is listed (zeros included) so gaps are visible too.
  const owasp = Object.keys(OWASP_TOP10).map((name) => ({
    name,
    value: 0,
    critical_high: 0,
  }));
  const owaspIndex = new Map(owasp.map((o) => [o.name, o]));
  let owaspMapped = 0;
  for (const i of open) {
    const categories = owaspCategories(i);
    if (categories.size) owaspMapped++;
    for (const c of categories) {
      const o = owaspIndex.get(c);
      o.value++;
      o.critical_high += Number(["critical", "high"].includes(i.severity));
    }
  }
  const { issues: _, ...metadata } = snapshot;
  return {
    snapshot: metadata,
    period: { start, end },
    filters,
    policy,
    metrics,
    previous: {
      new: prevNew,
      fixed: prevFixed,
      net_change: prevFixed - prevNew,
      start: previousStart,
      end: previousEnd,
    },
    trend,
    severity: SEVERITIES.map((name) => ({
      name,
      value: severity.find((s) => s.name === name)?.value || 0,
    })),
    aging: ["0–30", "31–90", "91–180", "181+"].map((name) => ({
      name,
      value: aging.find((s) => s.name === name)?.value || 0,
    })),
    sources: grouped(introduced, (i) => i.source),
    products,
    issue_types: grouped(open, (i) => i.issue_type || "Unknown"),
    exploit_maturity: grouped(open, (i) => i.exploit_maturity),
    cwes: top(each(open, "cwe")),
    owasp,
    owasp_mapped: owaspMapped,
    cves: top(each(open, "cve")),
    project_types: top(grouped(open, (i) => i.project_type || "Unknown"), 8),
    repositories: top(repositories, 2000),
    repository_total: repositories.length,
    packages: top(packages, 15),
    branches: grouped(open, (i) => i.target_ref || "Not set"),
    fixed_products: grouped(fixed, (i) => i.product),
    ranking: [...ranks.values()].sort(
      (a, b) => b.over_sla - a.over_sla || b.critical_high - a.critical_high,
    ),
    issues: all.slice(0, 250),
    issue_total: all.length,
    _all_issues: all,
    notes: [
      "Backlog and SLA aging use the snapshot date. The activity period filters introduction and resolution events.",
      "Latest lifecycle timestamps cannot recover every reopen/fix cycle. Event trends and MTTR are provisional.",
      "Positive net remediation means fixed minus introduced, not measured historical backlog change.",
      "Coverage, risk score and fix rate need additional inventory, approved weights or historical snapshots.",
      ...snapshot.warnings,
    ],
  };
}
