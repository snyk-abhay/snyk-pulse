import { useEffect, useState } from "react";
import { request } from "./api";
import type { AppState } from "./types";

type Column = { name: string; samples: string[]; numeric: boolean; filled: boolean };

// Ready-made definitions using columns present in Snyk issue exports.
export const metricExamples: { title: string; why: string; metric: object }[] = [
  {
    title: "Critical open findings",
    why: "Count rows that match every condition.",
    metric: {
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
  },
  {
    title: "Open secrets in GitHub repos",
    why: "Combine several conditions; 'in' matches any value in a list.",
    metric: {
      id: "github_secrets_open",
      label: "Open secrets · GitHub",
      dataset: "issues",
      window: "snapshot",
      aggregate: "count",
      where: [
        { field: "ISSUE_STATUS", op: "eq", value: "Open" },
        { field: "ISSUE_TYPE", op: "eq", value: "Secret" },
        { field: "PROJECT_ORIGIN", op: "in", value: ["github", "github-enterprise"] },
      ],
    },
  },
  {
    title: "Repositories with critical findings",
    why: "'distinct' counts unique values of a column.",
    metric: {
      id: "repos_with_critical",
      label: "Repos with criticals",
      dataset: "issues",
      window: "snapshot",
      aggregate: "distinct",
      field: "{REPO}",
      where: [
        { field: "ISSUE_STATUS", op: "eq", value: "Open" },
        { field: "ISSUE_SEVERITY", op: "eq", value: "Critical" },
      ],
    },
  },
  {
    title: "Fixable share of open findings",
    why: "'percentage' = rows matching numerator ÷ rows matching where.",
    metric: {
      id: "fixable_share",
      label: "Fixable share",
      dataset: "issues",
      window: "snapshot",
      aggregate: "percentage",
      unit: "%",
      where: [{ field: "ISSUE_STATUS", op: "eq", value: "Open" }],
      numerator: [{ field: "COMPUTED_FIXABILITY", op: "in", value: ["Fixable", "Partially Fixable"] }],
    },
  },
  {
    title: "Critical findings introduced this period",
    why: "'period' counts rows whose date falls in the dashboard's date range.",
    metric: {
      id: "critical_introduced",
      label: "Criticals introduced",
      dataset: "issues",
      window: "period",
      dateField: "FIRST_INTRODUCED",
      aggregate: "count",
      where: [{ field: "ISSUE_SEVERITY", op: "eq", value: "Critical" }],
    },
  },
  {
    title: "Average NVD score of open findings",
    why: "'mean' and 'sum' need a numeric column in field.",
    metric: {
      id: "avg_nvd_score",
      label: "Avg NVD score",
      dataset: "issues",
      window: "snapshot",
      aggregate: "mean",
      field: "NVD_SCORE",
      where: [
        { field: "ISSUE_STATUS", op: "eq", value: "Open" },
        { field: "NVD_SCORE", op: "present" },
      ],
    },
  },
];

const fields: [string, string, string][] = [
  ["id", "Required", "Unique lowercase name: letters, digits, underscore (e.g. critical_open)."],
  ["label", "Optional", "Title shown on the tile."],
  ["dataset", "Required", "Which loaded dataset to read, usually \"issues\"."],
  ["window", "Required", "\"snapshot\" = all current rows · \"period\" = only rows dated within the dashboard's From–To range."],
  ["dateField", "With period", "Date column used for the period window, e.g. FIRST_INTRODUCED or LAST_RESOLVED."],
  ["aggregate", "Required", "count · distinct · sum · mean · percentage."],
  ["field", "distinct/sum/mean", "Column to count unique values of, or to add up / average (must be numeric for sum and mean)."],
  ["where", "Optional", "Conditions every counted row must meet (AND)."],
  ["numerator", "percentage", "Extra conditions for the top of the fraction; the bottom is rows matching where."],
  ["unit", "Optional", "Suffix shown after the value, e.g. \"%\" or \"d\"."],
];
const operators: [string, string][] = [
  ["eq / ne", "equals / not equal (case-insensitive)"],
  ["in", "matches any value in a list: [\"High\", \"Critical\"]"],
  ["gt gte lt lte", "number comparisons (non-numbers never match)"],
  ["present", "column has any value (no value key needed)"],
];

// Snyk names the repository column differently per export (CSV vs Export API).
const REPO_COLUMNS = ["PROJECT_TARGET", "PROJECT_TARGET_DISPLAY_NAME", "ASSET_NAME", "PROJECT_NAME"];

// Fill placeholders with this dataset's real column names; returns null if a column is missing.
function adapt(metric: object, names: Set<string>): object | null {
  const repo = REPO_COLUMNS.find((c) => names.has(c));
  const text = JSON.stringify(metric).replaceAll("{REPO}", repo || "");
  const result = JSON.parse(text);
  const used = [
    result.field,
    result.dateField,
    ...[...(result.where || []), ...(result.numerator || [])].map((r: { field: string }) => r.field),
  ].filter(Boolean);
  return names.size && used.every((c: string) => names.has(c)) ? result : null;
}

export function MetricGuide({
  state,
  onInsert,
}: {
  state: AppState;
  onInsert: (metric: object) => void;
}) {
  const datasets = state.datasets.map((d) => d.name);
  const [dataset, setDataset] = useState(datasets.includes("issues") ? "issues" : datasets[0] || ""),
    [columns, setColumns] = useState<Column[]>([]),
    [filter, setFilter] = useState(""),
    [copied, setCopied] = useState("");
  useEffect(() => {
    if (!dataset) return;
    const controller = new AbortController();
    request<{ columns: Column[] }>("/api/columns?dataset=" + encodeURIComponent(dataset), {
      signal: controller.signal,
    })
      .then((r) => setColumns(r.columns))
      .catch(() => setColumns([]));
    return () => controller.abort();
  }, [dataset, state.version]);
  const copy = (name: string) => {
    void navigator.clipboard?.writeText(name).catch(() => {});
    setCopied(name);
    setTimeout(() => setCopied(""), 1200);
  };
  const shown = columns.filter((c) => c.name.toLowerCase().includes(filter.trim().toLowerCase()));
  return (
    <div className="metric-guide">
      <details open>
        <summary>How to build a custom metric</summary>
        <ol className="guide-steps">
          <li>
            <b>Pick a starting point.</b> Insert an example below, or edit the JSON in the editor.
            The editor holds a JSON <i>array</i> — one object per metric, separated by commas.
          </li>
          <li>
            <b>Use real column names.</b> Copy them from <i>Your columns</i> below. Headers are
            uppercase with spaces turned into underscores; values compare case-insensitively.
          </li>
          <li>
            <b>Click Apply metric definitions.</b> Pulse checks the JSON and shows any problem next
            to the editor. Applied metrics are saved and come back after a restart.
          </li>
          <li>
            <b>See the results</b> as tiles under <i>Your additional metrics</i> on every dashboard.
            They follow the dashboard's organization, product and severity filters and its date range.
          </li>
        </ol>
      </details>
      <details>
        <summary>Examples you can insert</summary>
        <div className="example-grid">
          {metricExamples.map((e) => (
            <div key={e.title} className="example-card">
              <b>{e.title}</b>
              <small>{e.why}</small>
              {(() => {
                const names = new Set(columns.map((c) => c.name));
                const ready = adapt(e.metric, names);
                const shownMetric = ready || e.metric;
                return (
                  <>
                    <pre>{JSON.stringify(shownMetric, null, 2).replaceAll('"{REPO}"', '"<repository column>"')}</pre>
                    {ready || !names.size ? (
                      <button onClick={() => onInsert(shownMetric)}>+ Insert into editor</button>
                    ) : (
                      <small className="muted">Your loaded data lacks a column this example uses.</small>
                    )}
                  </>
                );
              })()}
            </div>
          ))}
        </div>
      </details>
      <details>
        <summary>Field and operator reference</summary>
        <div className="reference-grid">
          <table>
            <thead>
              <tr>
                <th>Key</th>
                <th>When</th>
                <th>Meaning</th>
              </tr>
            </thead>
            <tbody>
              {fields.map(([key, when, meaning]) => (
                <tr key={key}>
                  <td><code>{key}</code></td>
                  <td>{when}</td>
                  <td>{meaning}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <table>
            <thead>
              <tr>
                <th>Operator (op)</th>
                <th>Meaning</th>
              </tr>
            </thead>
            <tbody>
              {operators.map(([op, meaning]) => (
                <tr key={op}>
                  <td><code>{op}</code></td>
                  <td>{meaning}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="muted">
          A condition looks like <code>{'{ "field": "ISSUE_SEVERITY", "op": "eq", "value": "High" }'}</code>.
          Up to 100 metrics and 25 conditions each. If a metric can't be calculated — a dataset isn't
          loaded or a column is missing — its tile shows the reason instead of a number.
        </p>
      </details>
      <details>
        <summary>
          Your columns{dataset ? ` · ${dataset}` : ""}
          {columns.length ? ` (${columns.length})` : ""}
        </summary>
        {datasets.length ? (
          <>
            <div className="table-controls">
              {datasets.length > 1 && (
                <select aria-label="Dataset columns" value={dataset} onChange={(e) => setDataset(e.target.value)}>
                  {datasets.map((d) => (
                    <option key={d} value={d}>{d}</option>
                  ))}
                </select>
              )}
              <input
                aria-label="Filter columns"
                placeholder="Filter columns"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
              <small className="muted">Click a column name to copy it.</small>
            </div>
            <div className="columns-table">
              {shown.map((c) => (
                <div key={c.name} className={c.filled ? "" : "empty-column"}>
                  <button className="column-name" onClick={() => copy(c.name)} title="Copy column name">
                    {copied === c.name ? "Copied ✓" : c.name}
                  </button>
                  <span className="column-kind">{c.filled ? (c.numeric ? "number" : "text") : "empty"}</span>
                  <span className="column-samples">
                    {c.samples.length ? c.samples.join(" · ") : "No values in this export"}
                  </span>
                </div>
              ))}
            </div>
          </>
        ) : (
          <p className="muted">Load a dataset to see its columns.</p>
        )}
      </details>
    </div>
  );
}
