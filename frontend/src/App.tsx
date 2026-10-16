import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { Chart } from "./Chart";
import { Brand, PolicyFields, Setup, ThemeToggle } from "./Setup";
import { before, mutate, titleCase, pretty, request, today } from "./api";
import { SavedData, startRefresh } from "./SavedData";
import { MetricGuide } from "./MetricGuide";
import { ReportGenerator } from "./ReportGenerator";
import { NavIcon, SnykMark } from "./Icons";
import { catalog, personaMetrics, personaQuestion } from "./catalog";
import { AppSecSections, CisoSections, EngineeringSections } from "./Personas";
import type {
  AppState,
  CustomMetric,
  Dashboard,
  Issue,
  Policy,
  Series,
} from "./types";

type Page =
  | "CISO"
  | "AppSec"
  | "Engineering"
  | "Organization"
  | "Explorer"
  | "Dictionary"
  | "Reports"
  | "Builder"
  | "Generate"
  | "Data"
  | "SLA";
const titles: Record<Page, string> = {
  CISO: "CISO dashboard",
  AppSec: "Application security",
  Engineering: "Engineering",
  Organization: "Organization scorecard",
  Explorer: "Metric explorer",
  Dictionary: "Metric dictionary",
  Reports: "Report library",
  Builder: "Report builder",
  Generate: "Generate report",
  Data: "Data & metrics",
  SLA: "SLA policy",
};
const navGroups: { label: string; pages: Page[] }[] = [
  {
    label: "DASHBOARDS",
    pages: ["CISO", "AppSec", "Engineering", "Organization"],
  },
  { label: "EXPLORE", pages: ["Explorer", "Dictionary"] },
  { label: "REPORTS", pages: ["Generate", "Reports", "Builder"] },
  { label: "CONFIGURE", pages: ["Data", "SLA"] },
];
// The chosen theme survives a refresh. index.html applies it before first paint;
// this reads the same key so React's state starts out matching it.
const THEME_KEY = "pulse-theme";
function savedTheme(): "dark" | "light" {
  try {
    return localStorage.getItem(THEME_KEY) === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}
// Theme tokens (design-tokens.css); Chart resolves them per theme.
export const palette = [
  "var(--cat1)",
  "var(--cat2)",
  "var(--cat3)",
  "var(--cat4)",
  "var(--cat5)",
];
export function Panel({
  title,
  sub,
  children,
  actions,
  fill = false,
}: {
  title: string;
  sub?: string;
  children: ReactNode;
  actions?: ReactNode;
  fill?: boolean;
}) {
  return (
    <section className={"panel" + (fill ? " panel-fill" : "")}>
      <div className="panel-heading">
        <div>
          <h2>{title}</h2>
          {sub && <p>{sub}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}
function Tile({
  id,
  value,
  label,
  unit,
  detail,
}: {
  id: string;
  value: number | null;
  label?: string;
  unit?: string;
  detail?: string;
}) {
  const spec = catalog[id];
  return (
    <div className="kpi" data-testid={"metric-" + id}>
      <div>
        {label || spec?.label || id}
        <span title={detail || spec?.detail}>ⓘ</span>
      </div>
      <strong>
        {pretty(value)}
        <small>{value == null ? "" : unit || spec?.unit}</small>
      </strong>
      <p>{detail || spec?.detail}</p>
    </div>
  );
}
export function Bars({
  values,
  label,
  horizontal = false,
  fill = false,
  showValues = false,
  categoryLabel,
  barLabel,
  tooltipLabel,
}: {
  values: Series;
  label: string;
  horizontal?: boolean;
  // Grow to the panel's remaining height instead of a fixed 240px.
  fill?: boolean;
  showValues?: boolean;
  // Optional axis text, an extra caption drawn on each bar, and tooltip text.
  categoryLabel?: (name: string) => string;
  barLabel?: (name: string) => string;
  tooltipLabel?: (name: string) => string;
}) {
  const axisText = (name: string) =>
    categoryLabel ? categoryLabel(name) : titleCase(name);
  const rows = horizontal ? [...values].reverse() : values;
  return (
    <Chart
      label={label}
      height={fill ? "fill" : 240}
      option={{
        color: palette,
        tooltip: {
          trigger: "axis",
          renderMode: "richText",
          ...(tooltipLabel
            ? {
                formatter: (items: { dataIndex: number; value: number }[]) => {
                  const item = items[0];
                  const row = rows[item.dataIndex];
                  return `${tooltipLabel(row.name)}\n${item.value.toLocaleString()} open findings`;
                },
              }
            : {}),
        },
        grid: {
          left: horizontal ? 125 : 45,
          right: 20,
          top: showValues ? 30 : 25,
          bottom: 42,
        },
        xAxis: horizontal
          ? { type: "value" }
          : {
              type: "category",
              data: values.map((v) => axisText(v.name)),
              axisLabel: { interval: 0, hideOverlap: !barLabel, fontSize: barLabel ? 11 : 12 },
            },
        yAxis: horizontal
          ? {
              type: "category",
              data: values.map((v) => titleCase(v.name)).reverse(),
            }
          : { type: "value" },
        series: [
          {
            type: "bar",
            barMaxWidth: horizontal ? 36 : 56,
            ...(showValues
              ? {
                  label: {
                    show: true,
                    position: horizontal ? "right" : "top",
                    color: "var(--text2)",
                    fontSize: 11,
                    formatter: ({ value }: { value: number }) => value.toLocaleString(),
                  },
                }
              : {}),
            data: rows.map((v, i) => ({
              value: v.value,
              itemStyle: {
                color: palette[i % palette.length],
                borderRadius: 3,
              },
              ...(barLabel && !horizontal
                ? {
                    // Rotated caption inside the bar; the value stays on top.
                    label: {
                      show: true,
                      position: "insideBottom",
                      rotate: 90,
                      align: "left",
                      verticalAlign: "middle",
                      distance: 8,
                      color: "#fff",
                      fontSize: 11,
                      fontWeight: 500,
                      formatter: barLabel(v.name),
                    },
                  }
                : {}),
            })),
          },
          ...(showValues && barLabel && !horizontal
            ? [
                {
                  type: "bar",
                  barMaxWidth: 56,
                  barGap: "-100%",
                  silent: true,
                  tooltip: { show: false },
                  itemStyle: { color: "transparent" },
                  label: {
                    show: true,
                    position: "top",
                    color: "var(--text2)",
                    fontSize: 11,
                    formatter: ({ value }: { value: number }) => value.toLocaleString(),
                  },
                  data: rows.map((v) => v.value),
                },
              ]
            : []),
        ],
      }}
    />
  );
}
export function Flow({ data }: { data: Dashboard }) {
  return (
    <Chart
      label="Introduced versus fixed weekly"
      option={{
        color: ["var(--cat1)", "var(--cat3)"],
        tooltip: { trigger: "axis", renderMode: "richText" },
        legend: { bottom: 0 },
        grid: { left: 48, right: 18, top: 20, bottom: 65 },
        xAxis: {
          type: "category",
          data: data.trend.map((t) => t.date.slice(5)),
          axisLabel: { hideOverlap: true },
        },
        yAxis: { type: "value" },
        series: [
          {
            name: "Introduced",
            type: "bar",
            barMaxWidth: 18,
            data: data.trend.map((t) => t.introduced),
          },
          {
            name: "Fixed",
            type: "bar",
            barMaxWidth: 18,
            data: data.trend.map((t) => t.fixed),
          },
        ],
      }}
    />
  );
}
const PAGE = 100;
// Short tags for Snyk products, so the table shows SCA/SAST/… at a glance.
const productTag = (product: string) => {
  const p = product.toLowerCase();
  if (p.includes("open source")) return "SCA";
  if (p.includes("code")) return "SAST";
  if (p.includes("container")) return "Container";
  if (p.includes("iac") || p.includes("infrastructure")) return "IaC";
  if (p.includes("secret")) return "Secrets";
  if (p.includes("dast") || p.includes("api & web") || p.includes("probely")) return "DAST";
  return product || "—";
};
type TableOptions = {
  severity: string[];
  product: string[];
  issue_type: string[];
  target: string[];
  org: { value: string; label: string }[];
};
const noTableFilters = { t_severity: "", t_product: "", t_org: "", t_type: "", t_target: "" };
function IssueTable({
  data,
  query,
  onIssue,
  repo = "",
  onRepoCleared,
}: {
  data: Dashboard;
  query: string;
  onIssue: (i: Issue) => void;
  repo?: string;
  onRepoCleared?: () => void;
}) {
  const [mode, setMode] = useState("all"),
    [search, setSearch] = useState(""),
    [term, setTerm] = useState(""),
    [rows, setRows] = useState<Issue[]>([]),
    [total, setTotal] = useState(data.issue_total),
    [loading, setLoading] = useState(false),
    [failed, setFailed] = useState(""),
    [tableFilters, setTableFilters] = useState(noTableFilters),
    [options, setOptions] = useState<TableOptions | null>(null);
  // A repository picked elsewhere (Engineering leaderboard) filters this table.
  useEffect(() => {
    if (repo) setTableFilters((f) => ({ ...f, t_target: repo }));
  }, [repo]);
  const filtersKey = JSON.stringify(tableFilters);
  const activeFilters = Object.values(tableFilters).filter(Boolean).length;
  const scroller = useRef<HTMLDivElement>(null),
    sentinel = useRef<HTMLDivElement>(null),
    inflight = useRef<AbortController | null>(null);
  // Debounce typing so each keystroke doesn't refetch.
  useEffect(() => {
    const id = setTimeout(() => setTerm(search.trim()), 250);
    return () => clearTimeout(id);
  }, [search]);
  const load = (offset: number) => {
    inflight.current?.abort();
    const controller = new AbortController();
    inflight.current = controller;
    setLoading(true);
    setFailed("");
    const params = new URLSearchParams(query);
    params.set("mode", mode);
    params.set("search", term);
    params.set("offset", String(offset));
    params.set("limit", String(PAGE));
    for (const [k, v] of Object.entries(tableFilters)) if (v) params.set(k, v);
    request<{ issues: Issue[]; total: number; options?: TableOptions }>(
      "/api/issues?" + params,
      { signal: controller.signal },
    )
      .then((page) => {
        setRows((prev) => (offset ? [...prev, ...page.issues] : page.issues));
        setTotal(page.total);
        if (page.options) setOptions(page.options);
      })
      .catch((e) => {
        if (e.name !== "AbortError") setFailed(e.message);
      })
      .finally(() => {
        if (inflight.current === controller) {
          inflight.current = null;
          setLoading(false);
        }
      });
  };
  // New scope, search or filter: start again from the top.
  useEffect(() => {
    scroller.current?.scrollTo({ top: 0 });
    load(0);
    return () => inflight.current?.abort();
  }, [query, mode, term, data, filtersKey]);
  // Load the next page when the bottom of the list scrolls into view.
  useEffect(() => {
    const target = sentinel.current;
    if (!target) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting && !inflight.current && rows.length < total)
          load(rows.length);
      },
      { root: scroller.current, rootMargin: "300px" },
    );
    observer.observe(target);
    return () => observer.disconnect();
  }, [rows.length, total, query, mode, term, filtersKey]);
  return (
    <Panel
      title="Remediation work list"
      sub={`${data.issue_total.toLocaleString()} open findings · ordered by SLA priority`}
      actions={
        <a className="button" href={"/api/reports/issues.csv?" + query}>
          Export CSV ↓
        </a>
      }
    >
      <div className="table-controls">
        <input
          aria-label="Search findings"
          placeholder="Search issue, project, ID or package"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          aria-label="Issue table filter"
          value={mode}
          onChange={(e) => setMode(e.target.value)}
        >
          <option value="all">All open findings</option>
          <option value="over">Over SLA</option>
          <option value="fixable">Fixable</option>
        </select>
        {(
          [
            ["t_severity", "Severity", options?.severity.map((v) => ({ value: v, label: titleCase(v) }))],
            ["t_product", "Product", options?.product.map((v) => ({ value: v, label: `${v} (${productTag(v)})` }))],
            ["t_type", "Type", options?.issue_type.map((v) => ({ value: v, label: v }))],
            ["t_org", "Organization", options?.org],
            ["t_target", "Repository", options?.target.map((v) => ({ value: v, label: v }))],
          ] as [keyof typeof noTableFilters, string, { value: string; label: string }[] | undefined][]
        ).map(([key, name, choices]) => (
          <select
            key={key}
            aria-label={`Filter by ${name.toLowerCase()}`}
            className={tableFilters[key] ? "filter-active" : ""}
            value={tableFilters[key]}
            onChange={(e) => setTableFilters({ ...tableFilters, [key]: e.target.value })}
          >
            <option value="">All {name === "Repository" ? "repositories" : name.toLowerCase() + (name === "Severity" ? "" : "s")}</option>
            {(choices || []).map((c) => (
              <option key={c.value} value={c.value}>
                {c.label}
              </option>
            ))}
          </select>
        ))}
        {activeFilters > 0 && (
          <button
            className="link-button"
            onClick={() => {
              setTableFilters(noTableFilters);
              onRepoCleared?.();
            }}
          >
            Clear {activeFilters} filter{activeFilters === 1 ? "" : "s"}
          </button>
        )}
      </div>
      <div className="table-scroll issue-scroll" ref={scroller}>
        <table>
          <thead>
            <tr>
              <th>Issue / project</th>
              <th>Severity</th>
              <th>Type</th>
              <th>Product</th>
              <th>Vulnerability</th>
              <th>Repository / target</th>
              <th>Organization</th>
              <th>Age</th>
              <th>SLA status</th>
              <th>Fix version</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((i) => (
              <tr key={i.key}>
                <td>
                  <button className="issue-link" onClick={() => onIssue(i)}>
                    {i.title}
                  </button>
                  <small>
                    {i.problem_id} · {i.project}
                  </small>
                </td>
                <td>
                  <span className={"severity " + i.severity}>
                    {titleCase(i.severity)}
                  </span>
                </td>
                <td>{i.issue_type || "—"}</td>
                <td>
                  <span className="product-tag" title={i.product}>
                    {productTag(i.product)}
                  </span>
                </td>
                <td className="vuln-ids">
                  {i.cve || i.cwe ? (
                    <>
                      {i.cve && <span title={i.cve}>{i.cve.split(", ").slice(0, 2).join(", ")}{i.cve.split(", ").length > 2 ? " …" : ""}</span>}
                      {i.cwe && <small title={i.cwe}>{i.cwe.split(", ").slice(0, 2).join(", ")}{i.cwe.split(", ").length > 2 ? " …" : ""}</small>}
                    </>
                  ) : (
                    "—"
                  )}
                </td>
                <td>
                  {i.target || "—"}
                  {i.target_ref && <small>{i.target_ref}</small>}
                </td>
                <td>{i.org}</td>
                <td>{i.age_days}d</td>
                <td>
                  <span className={i.over_sla ? "bad" : "good"}>
                    {i.over_sla
                      ? `${-i.days_to_sla}d overdue`
                      : `${i.days_to_sla}d remaining`}
                  </span>
                </td>
                <td>{i.fix_version || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <div ref={sentinel} className="scroll-sentinel" aria-hidden="true" />
        {loading && <p className="empty-inline">Loading findings…</p>}
        {failed && (
          <p className="empty-inline">
            {failed}{" "}
            <button onClick={() => load(rows.length)}>Retry</button>
          </p>
        )}
        {!loading && !failed && !rows.length && (
          <p className="empty-inline">No findings match these filters.</p>
        )}
      </div>
      <div className="table-footer">
        Showing {rows.length.toLocaleString()} of {total.toLocaleString()}
        {total !== data.issue_total ? " matching" : ""} findings
        {rows.length < total ? " · scroll for more" : ""}. CSV includes the full
        selected scope.
      </div>
    </Panel>
  );
}
const example = JSON.stringify(
  [
    {
      id: "critical_open",
      label: "Critical open",
      dataset: "issues",
      window: "snapshot",
      aggregate: "count",
      where: [
        { field: "ISSUE_STATUS", op: "eq", value: "Open" },
        { field: "ISSUE_SEVERITY", op: "eq", value: "Critical" },
      ],
    },
  ],
  null,
  2,
);
export default function App() {
  const [state, setState] = useState<AppState | null>(null),
    [data, setData] = useState<Dashboard | null>(null),
    [custom, setCustom] = useState<CustomMetric[]>([]),
    [page, setPage] = useState<Page>("CISO"),
    [setup, setSetup] = useState(false),
    [theme, setTheme] = useState<"dark" | "light">(savedTheme),
    [collapsed, setCollapsed] = useState(false),
    [revision, setRevision] = useState(0),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [loading, setLoading] = useState(false),
    [busy, setBusy] = useState(false);
  const [filters, setFilters] = useState<Record<string, string>>({
      org_id: "",
      product: "",
      severity: "",
    }),
    [period, setPeriod] = useState({ start: "", end: "" }),
    [policy, setPolicy] = useState<Policy>({
      critical: 15,
      high: 30,
      medium: 90,
      low: 180,
    }),
    [definitions, setDefinitions] = useState(example),
    [registryJSON, setRegistryJSON] = useState(
      '[\n  {"name": "custom_dataset", "label": "My dataset", "dateFilter": "updated"}\n]',
    ),
    [dictQ, setDictQ] = useState(""),
    [explMetric, setExplMetric] = useState("over_sla"),
    [explGroup, setExplGroup] = useState("org_id"),
    [explore, setExplore] = useState<{ name: string; value: number | null }[]>(
      [],
    ),
    [drawer, setDrawer] = useState<Issue | null>(null),
    [sections, setSections] = useState(["kpis", "trend", "aging", "table"]),
    [reportTitle, setReportTitle] = useState("Security posture report"),
    [repoFilter, setRepoFilter] = useState(""),
    [definitionsError, setDefinitionsError] = useState("");
  const query = new URLSearchParams({ ...filters, ...period }).toString();
  const refresh = () => setRevision((v) => v + 1);
  useEffect(() => {
    const controller = new AbortController();
    request<AppState>("/api/state", { signal: controller.signal })
      .then((s) => {
        setState(s);
        setPolicy(s.policy);
        setSetup(!s.datasets.length);
        setDefinitions(
          s.definitions.length
            ? JSON.stringify(s.definitions, null, 2)
            : example,
        );
      })
      .catch((e) => {
        if (e.name !== "AbortError") setError(e.message);
      });
    return () => controller.abort();
  }, []);
  useEffect(() => {
    if (!revision) return;
    const controller = new AbortController();
    request<AppState>("/api/state", { signal: controller.signal })
      .then((s) => {
        setState(s);
        setPolicy(s.policy);
      })
      .catch((e) => {
        if (e.name !== "AbortError") setError(e.message);
      });
    return () => controller.abort();
  }, [revision]);
  useEffect(() => {
    if (!state) return;
    const end = state.snapshot?.as_of || today();
    setPeriod((p) =>
      !p.end || p.end > end ? { start: before(end, 89), end } : p,
    );
  }, [state?.snapshot?.as_of, !!state]);
  useEffect(() => {
    if (!state?.job?.running) return;
    const id = setInterval(refresh, 1200);
    return () => clearInterval(id);
  }, [state?.job?.running]);
  useEffect(() => {
    if (!state || !period.start || !period.end) return;
    const controller = new AbortController();
    setLoading(true);
    setData(null);
    setCustom([]);
    const run = async () => {
      try {
        const [d, c] = await Promise.all([
          state.snapshot
            ? request<Dashboard>("/api/dashboard?" + query, {
                signal: controller.signal,
              })
            : Promise.resolve(null),
          request<CustomMetric[]>("/api/extensions?" + query, {
            signal: controller.signal,
          }),
        ]);
        setData(d);
        setCustom(c);
      } catch (e) {
        if ((e as Error).name !== "AbortError") setError((e as Error).message);
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    };
    void run();
    return () => controller.abort();
  }, [state, query, period.start, period.end]);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {
      // Storage unavailable: the choice just lasts until the page is refreshed.
    }
  }, [theme]);
  useEffect(() => {
    if (page !== "Explorer" || !state?.snapshot) return;
    const controller = new AbortController();
    setExplore([]);
    const opts = (state.options[explGroup] || []).slice(0, 50);
    void Promise.all(
      opts.map(async (o) => {
        const value = typeof o === "string" ? o : o.value,
          name = typeof o === "string" ? o : o.label;
        const q = new URLSearchParams({
          ...filters,
          ...period,
          [explGroup]: value,
        });
        const result = await request<Dashboard>("/api/dashboard?" + q, {
          signal: controller.signal,
        });
        return { name, value: result.metrics[explMetric] ?? null };
      }),
    )
      .then(setExplore)
      .catch((e) => {
        if (e.name !== "AbortError") setError(e.message);
      });
    return () => controller.abort();
  }, [page, state, explMetric, explGroup, query]);
  async function action(fn: () => Promise<unknown>, message: string) {
    setBusy(true);
    setError("");
    try {
      await fn();
      setNotice(message);
      refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const goto = (p: Page) => {
    setPage(p);
    setError("");
  };
  if (!state)
    return (
      <div className="loading-screen">
        <Brand />
        <p>{error || "Opening your local session…"}</p>
      </div>
    );
  if (setup)
    return (
      <Setup
        theme={theme}
        onToggleTheme={() => setTheme(theme === "dark" ? "light" : "dark")}
        state={state}
        refresh={refresh}
        onDone={() => {
          setSetup(false);
          setFilters({
            org_id: "",
            product: "",
            severity: "",
          });
          refresh();
        }}
        onCancel={state.datasets.length ? () => setSetup(false) : undefined}
      />
    );
  const persona = Object.hasOwn(personaMetrics, page),
    showFilters = persona || ["Explorer", "Builder", "Reports"].includes(page);
  // Parse locally first so JSON mistakes point at the problem instead of a generic error.
  const parseDefinitions = (): unknown[] | null => {
    try {
      const parsed = JSON.parse(definitions);
      if (!Array.isArray(parsed)) {
        setDefinitionsError("The editor must contain a JSON array: [ { …metric… }, { … } ].");
        return null;
      }
      return parsed;
    } catch (e) {
      const message = (e as Error).message;
      const at = /position (\d+)/.exec(message)?.[1];
      const line = at ? definitions.slice(0, Number(at)).split("\n").length : null;
      setDefinitionsError(
        `Invalid JSON${line ? ` near line ${line}` : ""}: ${message}. Check for a missing comma, quote or bracket.`,
      );
      return null;
    }
  };
  const saveDefinitions = async () => {
    setDefinitionsError("");
    const parsed = parseDefinitions();
    if (!parsed) return;
    setBusy(true);
    try {
      await mutate("/api/metrics", parsed, "PUT");
      setNotice(
        parsed.length
          ? `${parsed.length} custom metric${parsed.length === 1 ? "" : "s"} applied and saved. See them under “Your additional metrics” on each dashboard.`
          : "Custom metrics cleared.",
      );
      refresh();
    } catch (e) {
      setDefinitionsError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const insertMetric = (metric: object) => {
    setDefinitionsError("");
    let label = "";
    let failed = false;
    // Functional update: rapid clicks each build on the latest editor text.
    setDefinitions((current) => {
      let list: Record<string, unknown>[] = [];
      try {
        const parsed = JSON.parse(current || "[]");
        if (Array.isArray(parsed)) list = parsed;
      } catch {
        failed = true;
        return current;
      }
      const next = { ...(metric as Record<string, unknown>) };
      const ids = new Set(list.map((m) => m?.id));
      let n = 2;
      while (ids.has(next.id)) next.id = `${(metric as { id: string }).id}_${n++}`;
      label = String(next.label || next.id);
      return JSON.stringify([...list, next], null, 2);
    });
    if (failed) setDefinitionsError("Fix the JSON in the editor before inserting an example.");
    else setNotice(`Added “${label || (metric as { id: string }).id}” to the editor. Click Apply metric definitions to use it.`);
  };
  const reportURL = "/api/reports/metrics.csv?" + query;
  const demoData = state.snapshot?.source === "Synthetic demo";
  const groups = ((state.options.group || []) as string[]).filter(
    (g) => g !== "Unknown group",
  );
  // A name the user typed wins; otherwise use the group(s) in the data.
  const workspaceName = state.workspaceName
    ? state.workspaceName
    : demoData
      ? "Demo workspace"
      : groups.length === 1
        ? groups[0]
        : groups.length > 1
          ? `${groups.length} groups`
          : "Local workspace";
  const groupUnknown =
    !state.workspaceName && !demoData && !!state.groupLookup?.missing;
  const renameWorkspace = () => {
    const name = prompt(
      "Workspace name (leave empty to use the Snyk group name):",
      state.workspaceName || (groups.length === 1 ? groups[0] : ""),
    );
    if (name === null) return;
    void action(
      () => mutate("/api/workspace", { name: name.trim() || null }, "PUT"),
      name.trim() ? "Workspace renamed." : "Workspace name reset to the Snyk group.",
    );
  };
  const lookupGroup = async () => {
    setBusy(true);
    setError("");
    try {
      let response = await fetch("/api/groups/lookup", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Pulse-Local": "1" },
        body: "{}",
      });
      let body = await response.json().catch(() => ({}));
      if (response.status === 409 && body.needsToken) {
        const token = prompt(
          "Your CSV has no group columns. Paste a Snyk API token to look up the group for these orgs (it is saved locally):",
        );
        if (!token) return;
        response = await fetch("/api/groups/lookup", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Pulse-Local": "1" },
          body: JSON.stringify({ token: token.trim(), region: state.connectionRegion }),
        });
        body = await response.json().catch(() => ({}));
      }
      if (!response.ok) throw new Error(body.detail || "Group lookup failed.");
      setNotice(
        body.missing
          ? `Group found for some orgs; ${body.missing} org(s) aren't visible to this token.`
          : "Group names loaded from Snyk.",
      );
      refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const orgCount = state.options.org_id?.length || 0,
    sourceCount = state.datasets.length;
  const updatedAt = state.snapshot?.imported_at
    ? new Date(state.snapshot.imported_at)
    : null;
  const updated = updatedAt
    ? updatedAt.toLocaleDateString(undefined, {
        day: "numeric",
        month: "short",
        year: "numeric",
      })
    : null;
  const updatedFull = updatedAt
    ? `Last updated ${updatedAt.toLocaleString()} · data as of ${state.snapshot?.as_of}`
    : "No data loaded yet";
  return (
    <div className={"shell " + (collapsed ? "collapsed" : "")}>
      <aside className="sidebar">
        <Brand />
        <div className="workspace">
          <span className="workspace-icon" aria-hidden="true">
            <SnykMark />
          </span>
          <div>
            <span className="workspace-name">
              <b title={groups.length > 1 ? groups.join(", ") : workspaceName}>
                {workspaceName}
              </b>
              <button
                className="workspace-edit"
                aria-label="Rename workspace"
                title="Rename workspace"
                onClick={renameWorkspace}
              >
                ✎
              </button>
            </span>
            <small>
              {orgCount} {orgCount === 1 ? "org" : "orgs"} · {sourceCount}{" "}
              {sourceCount === 1 ? "data source" : "data sources"}
            </small>
            <small title={updatedFull}>
              {updated ? `Updated ${updated}` : "No data loaded"}
            </small>
            {groupUnknown && (
              <button
                className="workspace-lookup"
                disabled={busy || state.groupLookup?.running}
                title={
                  state.groupLookup?.message ||
                  "This CSV has no group columns. Look up the group from Snyk."
                }
                onClick={lookupGroup}
              >
                {state.groupLookup?.running ? "Looking up group…" : "Look up group →"}
              </button>
            )}
          </div>
        </div>
        <nav aria-label="Main navigation">
          {navGroups.map((g) => (
            <div key={g.label}>
              <p className="nav-label">{g.label}</p>
              {g.pages.map((p) => (
                <button
                  aria-label={titles[p]}
                  title={titles[p]}
                  className={page === p ? "active" : ""}
                  key={p}
                  onClick={() => goto(p)}
                >
                  <span className="nav-icon">
                    <NavIcon name={p} />
                  </span>
                  <span className="nav-text">{titles[p]}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>
        <button
          className="collapse-button"
          aria-label="Toggle sidebar"
          onClick={() => setCollapsed(!collapsed)}
        >
          {collapsed ? "⇥" : "⇤ Collapse"}
        </button>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumbs">
            {workspaceName} <span>/</span> <b>{titles[page]}</b>
          </div>
          <div className="top-actions">
            <span className="session-status">
              <i />
              {state.snapshot?.source || "Session ready"}
            </span>
            {state.store?.source?.kind === "api" && (
              <button
                disabled={busy || !!state.job?.running}
                title="Pull the saved Snyk scope again up to today"
                onClick={async () => {
                  setBusy(true);
                  setError("");
                  const result = await startRefresh(null);
                  setBusy(false);
                  if (result.started) {
                    setNotice("Refreshing from Snyk up to today.");
                    refresh();
                  } else {
                    setError(result.detail);
                    if (result.needsToken) goto("Data");
                  }
                }}
              >
                ↻ Refresh
              </button>
            )}
            <button onClick={() => setSetup(true)}>↑ Add data</button>
            <ThemeToggle
              theme={theme}
              onToggle={() => setTheme(theme === "dark" ? "light" : "dark")}
            />
            <span className="workspace-meta" title={updatedFull}>
              <b>{workspaceName}</b>
              <small>
                {orgCount} {orgCount === 1 ? "org" : "orgs"} · {sourceCount}{" "}
                {sourceCount === 1 ? "source" : "sources"}
                {updated ? ` · Updated ${updated}` : ""}
              </small>
            </span>
          </div>
        </header>
        <main>
          <div className="page-heading">
            <h1>{titles[page]}</h1>
            {persona && (
              <div className="segments" aria-label="Persona dashboards">
                {(["CISO", "AppSec", "Engineering"] as Page[]).map((p) => (
                  <button
                    key={p}
                    className={page === p ? "selected" : ""}
                    onClick={() => goto(p)}
                  >
                    {p === "AppSec" ? "AppSec" : p}
                  </button>
                ))}
              </div>
            )}
            {page === "CISO" && data && (
              <button
                className="primary"
                onClick={() => {
                  setReportTitle("Executive board summary");
                  goto("Builder");
                }}
              >
                Prepare board report
              </button>
            )}
          </div>
          {error && (
            <div className="alert error" role="alert">
              {error}
              <button aria-label="Dismiss error" onClick={() => setError("")}>
                ×
              </button>
            </div>
          )}
          {notice && (
            <div className="alert good" role="status">
              {notice}
              <button aria-label="Dismiss notice" onClick={() => setNotice("")}>
                ×
              </button>
            </div>
          )}
          {state.job && (
            <div
              className={
                "alert " + (state.job.stage === "error" ? "error" : "")
              }
              role="status"
            >
              <span>
                {state.job.running ? "↻ " : ""}
                {state.job.message}
              </span>
              {state.job.running && (
                <button
                  onClick={() =>
                    action(
                      () => mutate("/api/cancel"),
                      "Cancellation requested.",
                    )
                  }
                >
                  Cancel pull
                </button>
              )}
            </div>
          )}
          {showFilters && (
            <section className="filterbar" aria-label="Dashboard filters">
              <div className="filter-fields">
                {[
                  ["org_id", "Organization"],
                  ["product", "Product"],
                  ["severity", "Severity"],
                ].map(([key, label]) => (
                  <label key={key}>
                    {label}
                    <select
                      aria-label={label}
                      value={filters[key]}
                      onChange={(e) =>
                        setFilters({ ...filters, [key]: e.target.value })
                      }
                    >
                      <option value="">All</option>
                      {(state.options[key] || []).map((o) => (
                        <option
                          key={typeof o === "string" ? o : o.value}
                          value={typeof o === "string" ? o : o.value}
                        >
                          {typeof o === "string" ? titleCase(o) : o.label}
                        </option>
                      ))}
                    </select>
                  </label>
                ))}
              </div>
              <div className="filter-period">
                <div className="segments">
                  {[7, 30, 90, 365].map((n) => (
                    <button
                      key={n}
                      onClick={() => {
                        const end = state.snapshot?.as_of || today();
                        setPeriod({ start: before(end, n - 1), end });
                      }}
                    >
                      {n === 365 ? "12m" : n + "d"}
                    </button>
                  ))}
                </div>
                <label>
                  From
                  <input
                    aria-label="Period start"
                    type="date"
                    value={period.start}
                    max={period.end}
                    onChange={(e) =>
                      setPeriod({ ...period, start: e.target.value })
                    }
                  />
                </label>
                <label>
                  To
                  <input
                    aria-label="Period end"
                    type="date"
                    value={period.end}
                    max={state.snapshot?.as_of || today()}
                    onChange={(e) =>
                      setPeriod({ ...period, end: e.target.value })
                    }
                  />
                </label>
                <button
                  className="text-button"
                  onClick={() =>
                    setFilters({
                      org_id: "",
                      product: "",
                      severity: "",
                    })
                  }
                >
                  Clear filters
                </button>
              </div>
            </section>
          )}
          {persona && (
            <>
              {!state.snapshot ? (
                <Panel title="Load issues to see your security posture">
                  <p>
                    Your other datasets are ready in Data & metrics. Import or
                    pull issues for these dashboards.
                  </p>
                  <button className="primary" onClick={() => setSetup(true)}>
                    Add issues
                  </button>
                </Panel>
              ) : loading ? (
                <div className="empty-inline" role="status">
                  Calculating metrics…
                </div>
              ) : (
                data && (
                  <>
                    <p className="persona-question">{personaQuestion[page]}</p>
                    <div className="snapshot-caption">
                      Snapshot {data.snapshot.as_of} ·{" "}
                      {state.count.toLocaleString()} findings loaded · activity{" "}
                      {period.start} — {period.end}
                    </div>
                    <div className="kpi-grid">
                      {personaMetrics[page].map((id) => (
                        <Tile key={id} id={id} value={data.metrics[id]} />
                      ))}
                    </div>
                    {page === "AppSec" ? (
                      <AppSecSections data={data} />
                    ) : page === "Engineering" ? (
                      <EngineeringSections
                        data={data}
                        onRepo={(repo) => {
                          setRepoFilter(repo);
                          requestAnimationFrame(() =>
                            document
                              .querySelector(".issue-scroll")
                              ?.scrollIntoView({ behavior: "smooth", block: "center" }),
                          );
                        }}
                      />
                    ) : (
                      <CisoSections
                        data={data}
                        onOrg={(orgId) => {
                          setFilters({ ...filters, org_id: orgId });
                          goto("Organization");
                        }}
                      />
                    )}
                    {custom.length > 0 && (
                      <Panel title="Your additional metrics">
                        <div className="kpi-grid custom-grid">
                          {custom.map((m) => (
                            <Tile
                              key={m.id}
                              id={m.id}
                              value={m.value}
                              label={m.label}
                              unit={m.unit}
                              detail={m.reason || `${m.dataset} · ${m.window}`}
                            />
                          ))}
                        </div>
                      </Panel>
                    )}
                    <IssueTable
                      data={data}
                      query={query}
                      onIssue={setDrawer}
                      repo={repoFilter}
                      onRepoCleared={() => setRepoFilter("")}
                    />
                    <details className="data-notes">
                      <summary>
                        About these numbers · definitions & data quality
                      </summary>
                      <ul>
                        {data.notes.map((n) => (
                          <li key={n}>{n}</li>
                        ))}
                      </ul>
                    </details>
                  </>
                )
              )}
            </>
          )}
          {page === "Explorer" && (
            <>
              <Panel
                title="Explore a metric"
                sub="Group the same calculation by organization, product or severity."
              >
                <div className="two-fields">
                  <label>
                    Metric
                    <select
                      value={explMetric}
                      onChange={(e) => setExplMetric(e.target.value)}
                    >
                      {Object.entries(catalog).map(([id, m]) => (
                        <option value={id} key={id}>
                          {m.label}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Group by
                    <select
                      value={explGroup}
                      onChange={(e) => setExplGroup(e.target.value)}
                    >
                      {[
                        ["org_id", "Organization"],
                        ["product", "Product"],
                        ["severity", "Severity"],
                      ].map(([v, l]) => (
                        <option value={v} key={v}>
                          {l}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
                <p>
                  {catalog[explMetric].detail} Grouping replaces the filter for
                  that dimension. Up to 50 groups.
                </p>
                {explore.some((r) => r.value !== null) ? (
                  <Bars
                    label="Metric grouped comparison"
                    horizontal
                    values={explore.filter((r) => r.value !== null) as Series}
                  />
                ) : (
                  <div className="empty-inline">
                    {state.snapshot
                      ? "No available values for this metric."
                      : "Load an issues dataset to explore built-in metrics."}
                  </div>
                )}
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Group</th>
                        <th>{catalog[explMetric].label}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {explore.map((r) => (
                        <tr key={r.name}>
                          <td>{titleCase(r.name)}</td>
                          <td>
                            {pretty(r.value)}
                            {r.value == null ? "" : catalog[explMetric].unit}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>
              <button onClick={() => goto("Data")}>
                Add a metric from another dataset →
              </button>
            </>
          )}
          {page === "Dictionary" && (
            <Panel
              title="Every number, explained"
              sub="Snapshot metrics use the current export. Activity metrics use the selected period."
            >
              <input
                className="dictionary-search"
                aria-label="Search metric dictionary"
                placeholder="Search metrics or definitions"
                value={dictQ}
                onChange={(e) => setDictQ(e.target.value)}
              />
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Metric</th>
                      <th>Definition / availability</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(catalog)
                      .filter(([id, m]) =>
                        (id + m.label + m.detail)
                          .toLowerCase()
                          .includes(dictQ.toLowerCase()),
                      )
                      .map(([id, m]) => (
                        <tr key={id}>
                          <td>
                            <b>{m.label}</b>
                            <small>{id}</small>
                          </td>
                          <td>{m.detail}</td>
                        </tr>
                      ))}
                    {state.definitions
                      .filter((m) =>
                        (m.id + m.label)
                          .toLowerCase()
                          .includes(dictQ.toLowerCase()),
                      )
                      .map((m) => (
                        <tr key={m.id}>
                          <td>
                            <b>{m.label}</b>
                            <small>{m.id} · custom</small>
                          </td>
                          <td>
                            {m.aggregate} · {m.dataset} · {m.window}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </Panel>
          )}
          {page === "Data" && (
            <>
              <Panel
                title="Saved data & versions"
                sub="Every API pull and CSV import is saved locally as a dated version and reopened on the next launch."
              >
                <SavedData
                  state={state}
                  onChanged={(message) => {
                    setError("");
                    setNotice(message);
                    refresh();
                  }}
                  onError={setError}
                />
              </Panel>
              <Panel
                title="Session datasets"
                sub="Import CSVs or pull selected Export API datasets. Each load is saved as a new version."
                actions={
                  <button className="primary" onClick={() => setSetup(true)}>
                    Add data
                  </button>
                }
              >
                <div className="dataset-grid">
                  {state.registry.map((d) => {
                    const loaded = state.datasets.find(
                      (x) => x.name === d.name,
                    );
                    return (
                      <div className="dataset-card" key={d.name}>
                        <h3>{d.label}</h3>
                        <code>{d.name}</code>
                        <p>
                          {loaded
                            ? `${loaded.rows.toLocaleString()} rows · ${loaded.headers.length} columns`
                            : "Not loaded"}
                        </p>
                        {loaded && (
                          <>
                            <a
                              href={
                                "/api/datasets/" +
                                encodeURIComponent(d.name) +
                                ".csv"
                              }
                            >
                              Download CSV ↓
                            </a>
                            <details>
                              <summary>Available columns</summary>
                              <div className="columns-list">
                                {loaded.headers.map((h) => (
                                  <code key={h}>{h}</code>
                                ))}
                              </div>
                            </details>
                          </>
                        )}
                      </div>
                    );
                  })}
                </div>
              </Panel>
              <Panel
                title="Add your own metrics"
                sub="Turn any column in your data into a dashboard tile: count, distinct, sum, mean or percentage, with your own conditions."
              >
                <MetricGuide state={state} onInsert={insertMetric} />
                <div className="editor-toolbar">
                  <label>
                    Load definitions JSON
                    <input
                      type="file"
                      accept=".json,application/json"
                      onChange={async (e) => {
                        const f = e.target.files?.[0];
                        if (f) {
                          if (f.size > 1024 * 1024) {
                            setError("Definitions exceed 1 MiB.");
                            return;
                          }
                          setDefinitions(await f.text());
                        }
                      }}
                    />
                  </label>
                  <button
                    onClick={() => {
                      const url = URL.createObjectURL(
                        new Blob([definitions], { type: "application/json" }),
                      );
                      const a = document.createElement("a");
                      a.href = url;
                      a.download = "pulse-metrics.json";
                      a.click();
                      setTimeout(() => URL.revokeObjectURL(url), 1000);
                    }}
                  >
                    Save definitions file ↓
                  </button>
                </div>
                <textarea
                  aria-label="Metric definitions JSON"
                  spellCheck={false}
                  value={definitions}
                  onChange={(e) => {
                    setDefinitions(e.target.value);
                    setDefinitionsError("");
                  }}
                  rows={16}
                  className={definitionsError ? "invalid" : ""}
                />
                {definitionsError && (
                  <p className="alert error" role="alert">
                    {definitionsError}
                  </p>
                )}
                <div className="form-actions">
                  <small>
                    Applying replaces all custom metrics with what's in the editor and saves them
                    locally. Apply an empty array <code>[]</code> to remove them.
                  </small>
                  <button
                    className="primary"
                    disabled={busy}
                    onClick={saveDefinitions}
                  >
                    Apply metric definitions
                  </button>
                </div>
                {custom.length > 0 && (
                  <div className="kpi-grid custom-grid">
                    {custom.map((m) => (
                      <Tile
                        key={m.id}
                        id={m.id}
                        value={m.value}
                        label={m.label}
                        unit={m.unit}
                        detail={m.reason || `${m.dataset} · ${m.window}`}
                      />
                    ))}
                  </div>
                )}
              </Panel>
              <Panel
                title="Register another dataset"
                sub="Add a dataset supported by your Snyk Export API, or a local CSV dataset. Registration does not grant API access."
              >
                <textarea
                  aria-label="Dataset registry JSON"
                  value={registryJSON}
                  onChange={(e) => setRegistryJSON(e.target.value)}
                  rows={5}
                />
                <button
                  disabled={busy}
                  onClick={() =>
                    action(
                      () => mutate("/api/registry", JSON.parse(registryJSON)),
                      "Dataset registered. It is now available in Add data.",
                    )
                  }
                >
                  Register dataset
                </button>
                <p>
                  For custom API routes beyond Export API datasets, add a
                  JavaScript adapter in lib/snyk.mjs. See the utility’s
                  EXTENSIONS.md guide.
                </p>
              </Panel>
            </>
          )}
          {page === "SLA" && (
            <Panel
              title="Your remediation deadlines"
              sub="Shared by all views and exports. Changes last for this session."
            >
              <form
                className="policy-form"
                onSubmit={(e) => {
                  e.preventDefault();
                  void action(
                    () => mutate("/api/policy", policy, "PUT"),
                    "SLA policy saved. All views and exports use the updated deadlines.",
                  );
                }}
              >
                <PolicyFields policy={policy} setPolicy={setPolicy} />
                <p>
                  UTC calendar days from first introduction. The deadline day is
                  compliant.
                </p>
                <button className="primary" disabled={busy}>
                  Save SLA policy
                </button>
              </form>
            </Panel>
          )}
          {page === "Generate" && (
            <ReportGenerator
              state={state}
              workspaceName={workspaceName}
              onNotice={(m) => {
                setError("");
                setNotice(m);
              }}
              onError={setError}
            />
          )}
          {page === "Reports" && (
            <>
              <p className="muted">
                Reports use the selected scope, date range and SLA policy. Print
                a report to save it as PDF.
              </p>
              <div className="report-grid">
                {[
                  [
                    "Monthly CISO posture",
                    "KPIs, weekly flow, aging and a remediation list.",
                    "builder",
                  ],
                  [
                    "Executive board summary",
                    "Security posture, progress and data limitations.",
                    "executive",
                  ],
                  [
                    "SLA breach report",
                    "Every open finding beyond its severity deadline.",
                    "breaches",
                  ],
                  [
                    "Open remediation queue",
                    "All open findings, including available fix versions.",
                    "issues",
                  ],
                  [
                    "Metric data export",
                    "All built-in and additional metric values with scope.",
                    "metrics",
                  ],
                  [
                    "Organization scorecard",
                    "Select an organization above to prepare its report.",
                    "organization",
                  ],
                ].map(([name, desc, type]) => (
                  <section className="panel report-card" key={type}>
                    <div className="report-illustration">
                      <span />
                      <span />
                      <span />
                      <span />
                      <span />
                    </div>
                    <h2>{name}</h2>
                    <p>{desc}</p>
                    {["breaches", "issues", "metrics"].includes(type) ? (
                      <a
                        aria-disabled={!data}
                        className={"button " + (!data ? "disabled" : "")}
                        href={
                          data
                            ? type === "metrics"
                              ? reportURL
                              : "/api/reports/issues.csv?" +
                                query +
                                (type === "breaches" ? "&over_sla=true" : "")
                            : undefined
                        }
                      >
                        Download CSV ↓
                      </a>
                    ) : (
                      <button
                        disabled={!data}
                        onClick={() => {
                          setReportTitle(name);
                          setSections(
                            type === "executive"
                              ? ["kpis", "trend", "aging"]
                              : ["kpis", "trend", "aging", "table"],
                          );
                          goto("Builder");
                        }}
                      >
                        Build report →
                      </button>
                    )}
                  </section>
                ))}
              </div>
              <Panel title="Run reports from your scheduler">
                <p>
                  For recurring local reports, schedule the CLI with cron or
                  your operating system’s scheduler. Each run pulls fresh data,
                  writes files, and exits.
                </p>
                <code className="command">
                  node snyk-pulse/pulse.mjs --org YOUR_ORG_UUID --out ./reports
                  --no-serve
                </code>
                <small>
                  Supply SNYK_TOKEN through your scheduler’s environment. This
                  utility does not send email or Slack messages.
                </small>
              </Panel>
            </>
          )}
          {page === "Builder" && (
            <div className="builder">
              <section className="panel builder-controls">
                <h2>Report content</h2>
                <label>
                  Report title
                  <input
                    value={reportTitle}
                    onChange={(e) => setReportTitle(e.target.value)}
                  />
                </label>
                {[
                  ["kpis", "Key metrics"],
                  ["trend", "Introduced vs. fixed"],
                  ["aging", "Backlog aging"],
                  ["table", "Remediation list"],
                ].map(([id, label]) => (
                  <label className="check-label" key={id}>
                    <input
                      type="checkbox"
                      checked={sections.includes(id)}
                      onChange={(e) =>
                        setSections(
                          e.target.checked
                            ? [...sections, id]
                            : sections.filter((v) => v !== id),
                        )
                      }
                    />
                    {label}
                  </label>
                ))}
                <button
                  className="primary"
                  disabled={!data || loading}
                  onClick={() => window.print()}
                >
                  Print / save PDF
                </button>
                {data && (
                  <a className="button" href={reportURL}>
                    Download metric CSV
                  </a>
                )}
                <small>
                  PDF uses your browser’s print dialog. The remediation list is
                  capped at 250; CSV includes all findings.
                </small>
              </section>
              <article className="report-preview">
                {data ? (
                  <>
                    <Brand />
                    <div className="eyebrow">
                      SECURITY POSTURE · {data.snapshot.as_of}
                    </div>
                    <h1>{reportTitle}</h1>
                    <p>
                      {period.start} — {period.end} ·{" "}
                      {Object.entries(filters)
                        .filter(([, v]) => v)
                        .map(([k, v]) => `${k}: ${v}`)
                        .join(" · ") || "All loaded data"}
                    </p>
                    {sections.includes("kpis") && (
                      <div className="kpi-grid">
                        {personaMetrics.CISO.map((id) => (
                          <Tile key={id} id={id} value={data.metrics[id]} />
                        ))}
                      </div>
                    )}
                    {sections.includes("trend") && (
                      <Panel title="Introduced vs. fixed">
                        <Flow data={data} />
                      </Panel>
                    )}
                    {sections.includes("aging") && (
                      <Panel title="Open issue aging">
                        <Bars values={data.aging} label="Report issue aging" />
                      </Panel>
                    )}
                    {sections.includes("table") && (
                      <IssueTable
                        data={data}
                        query={query}
                        onIssue={setDrawer}
                      />
                    )}
                    <h3>Methodology & limitations</h3>
                    <ul>
                      {data.notes.map((n) => (
                        <li key={n}>{n}</li>
                      ))}
                    </ul>
                    <p>
                      SLA days:{" "}
                      {Object.entries(data.policy)
                        .map(([s, d]) => `${titleCase(s)} ${d}`)
                        .join(" · ")}
                      .
                    </p>
                  </>
                ) : (
                  <div className="empty-inline">
                    Load an issues dataset to build a report.
                  </div>
                )}
              </article>
            </div>
          )}
          <footer>
            <span>SNYK PULSE / JavaScript utility v0.2</span>
            <span>Local session · stop with Ctrl+C</span>
          </footer>
        </main>
      </div>
      {drawer && (
        <div className="drawer-backdrop" onClick={() => setDrawer(null)}>
          <section
            className="drawer"
            role="dialog"
            aria-modal="true"
            aria-label="Finding details"
            onClick={(e) => e.stopPropagation()}
            onKeyDown={(e) => {
              if (e.key === "Escape") setDrawer(null);
            }}
          >
            <button
              autoFocus
              className="drawer-close"
              aria-label="Close finding details"
              onClick={() => setDrawer(null)}
            >
              ×
            </button>
            <span className={"severity " + drawer.severity}>
              {titleCase(drawer.severity)}
            </span>
            <h2>{drawer.title}</h2>
            <code>{drawer.problem_id}</code>
            <dl>
              {[
                ["Project", drawer.project],
                ["Organization", drawer.org],
                ["Product", `${drawer.product} (${productTag(drawer.product)})`],
                ["Type", drawer.issue_type || "—"],
                ["Repository / target", drawer.target ? drawer.target + (drawer.target_ref ? ` @ ${drawer.target_ref}` : "") : "—"],
                ["CVE", drawer.cve || "—"],
                ["CWE", drawer.cwe || "—"],
                ["Package", drawer.package || "—"],
                ["Age", drawer.age_days + " days"],
                ["SLA", drawer.over_sla ? "Overdue" : "Within deadline"],
                ["Fix version", drawer.fix_version || "Unavailable"],
                [
                  "Exploitable",
                  drawer.exploitable == null
                    ? "Unknown"
                    : drawer.exploitable
                      ? "Yes"
                      : "No",
                ],
                [
                  "Reachable",
                  drawer.reachable == null
                    ? "Unknown"
                    : drawer.reachable
                      ? "Yes"
                      : "No",
                ],
              ].map(([k, v]) => (
                <div key={k}>
                  <dt>{k}</dt>
                  <dd>{v}</dd>
                </div>
              ))}
            </dl>
          </section>
        </div>
      )}
    </div>
  );
}
