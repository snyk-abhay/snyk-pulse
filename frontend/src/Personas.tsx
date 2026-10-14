import { useState } from "react";
import { Chart } from "./Chart";
import { Bars, Flow, Panel, palette } from "./App";
import { pretty, titleCase } from "./api";
import type { Dashboard } from "./types";

// Short names for frequently seen CWEs (MITRE titles, abbreviated for axis labels).
const CWE_NAMES: Record<string, [string, string]> = {
  "CWE-20": ["Input validation", "Improper Input Validation"],
  "CWE-22": ["Path traversal", "Path Traversal"],
  "CWE-78": ["OS command injection", "OS Command Injection"],
  "CWE-79": ["XSS", "Cross-site Scripting"],
  "CWE-89": ["SQL injection", "SQL Injection"],
  "CWE-94": ["Code injection", "Code Injection"],
  "CWE-119": ["Memory buffer bounds", "Improper Restriction of Operations within Memory Buffer Bounds"],
  "CWE-120": ["Buffer overflow", "Classic Buffer Overflow"],
  "CWE-125": ["Out-of-bounds read", "Out-of-bounds Read"],
  "CWE-190": ["Integer overflow", "Integer Overflow or Wraparound"],
  "CWE-200": ["Info exposure", "Exposure of Sensitive Information"],
  "CWE-269": ["Privilege mgmt", "Improper Privilege Management"],
  "CWE-276": ["Default perms", "Incorrect Default Permissions"],
  "CWE-287": ["Authentication", "Improper Authentication"],
  "CWE-295": ["Cert validation", "Improper Certificate Validation"],
  "CWE-327": ["Weak crypto", "Broken or Risky Cryptographic Algorithm"],
  "CWE-352": ["CSRF", "Cross-Site Request Forgery"],
  "CWE-400": ["Resource use", "Uncontrolled Resource Consumption"],
  "CWE-401": ["Memory leak", "Missing Release of Memory after Effective Lifetime"],
  "CWE-416": ["Use after free", "Use After Free"],
  "CWE-434": ["File upload", "Unrestricted Upload of Dangerous File Type"],
  "CWE-476": ["NULL deref", "NULL Pointer Dereference"],
  "CWE-502": ["Deserialization", "Deserialization of Untrusted Data"],
  "CWE-547": ["Hard-coded consts", "Use of Hard-coded, Security-relevant Constants"],
  "CWE-601": ["Open redirect", "Open Redirect"],
  "CWE-611": ["XXE", "XML External Entity Reference"],
  "CWE-770": ["No resource limits", "Allocation of Resources Without Limits or Throttling"],
  "CWE-772": ["Resource leak", "Missing Release of Resource after Effective Lifetime"],
  "CWE-787": ["Out-of-bounds write", "Out-of-bounds Write"],
  "CWE-798": ["Hard-coded credentials", "Use of Hard-coded Credentials"],
  "CWE-835": ["Infinite loop", "Loop with Unreachable Exit Condition"],
  "CWE-862": ["Missing authz", "Missing Authorization"],
  "CWE-918": ["SSRF", "Server-Side Request Forgery"],
  "CWE-1321": ["Prototype pollution", "Prototype Pollution"],
};

const severityColors = [
  "var(--sev-c)",
  "var(--sev-h)",
  "var(--sev-m)",
  "var(--sev-l)",
];

function Donut({
  label,
  values,
  colors,
}: {
  label: string;
  values: { name: string; value: number }[];
  colors?: string[];
}) {
  return (
    <Chart
      label={label}
      option={{
        color: colors || palette,
        tooltip: { trigger: "item", renderMode: "richText" },
        legend: { bottom: 8, type: "scroll" },
        series: [
          {
            type: "pie",
            radius: ["48%", "70%"],
            center: ["50%", "43%"],
            label: { show: false },
            data: values.map((v) => ({ ...v, name: titleCase(v.name) })),
          },
        ],
      }}
    />
  );
}

function FlowPanel({ data }: { data: Dashboard }) {
  return (
    <Panel
      title="Risk trend · introduced vs. fixed"
      sub="Weekly activity in the selected period"
    >
      <div className="flow-totals">
        <span>
          <i style={{ background: palette[0] }} />
          Introduced <b>{pretty(data.metrics.new)}</b>
        </span>
        <span>
          <i style={{ background: palette[2] }} />
          Fixed <b>{pretty(data.metrics.fixed)}</b>
        </span>
        <span>
          Net remediation <b>{pretty(data.metrics.net_change)}</b>
        </span>
      </div>
      <Flow data={data} />
    </Panel>
  );
}

type Ranked = { key: string; name: string; sub: string; value: number; of: number; onClick?: () => void };
function Ranking({ rows, empty, valueLabel }: { rows: Ranked[]; empty: string; valueLabel: string }) {
  return (
    <div className="rankings">
      {rows.map((r, i) => (
        <button key={r.key} onClick={r.onClick} disabled={!r.onClick} title={`${r.value} ${valueLabel}`}>
          <span className="rank">{i + 1}</span>
          <span className="rank-name">
            <b>{r.name}</b>
            <small>{r.sub}</small>
          </span>
          <span className="rank-track">
            <i style={{ width: (r.of ? (r.value / r.of) * 100 : 0) + "%" }} />
          </span>
          <b>{r.value.toLocaleString()}</b>
          {r.onClick && <span>›</span>}
        </button>
      ))}
      {!rows.length && <p>{empty}</p>}
    </div>
  );
}

/** CISO: overall posture, trend, product risk and organization accountability. */
export function CisoSections({
  data,
  onOrg,
}: {
  data: Dashboard;
  onOrg: (orgId: string) => void;
}) {
  return (
    <>
      <div className="chart-grid">
        <FlowPanel data={data} />
        <Panel title="Open backlog by severity" sub="At the snapshot date">
          <Donut label="Open issues by severity" values={data.severity} colors={severityColors} />
        </Panel>
      </div>
      <div className="chart-grid">
        <Panel
          title="Risk by product"
          sub="Open Critical + High findings per Snyk product"
        >
          <Bars
            label="Critical and high findings by product"
            horizontal
            values={data.products.map((p) => ({ name: p.name, value: p.critical_high }))}
          />
        </Panel>
        <Panel
          title="Organizations over SLA"
          sub="Findings past deadline · select an organization for its scorecard"
        >
          <Ranking
            valueLabel="over SLA"
            empty="No open findings in this scope."
            rows={data.ranking.slice(0, 6).map((r) => ({
              key: r.org_id,
              name: r.org,
              sub: `${r.open.toLocaleString()} open · ${r.critical_high.toLocaleString()} critical/high`,
              value: r.over_sla,
              of: r.open,
              onClick: () => onOrg(r.org_id),
            }))}
          />
        </Panel>
      </div>
      <Panel title="Open issue aging" sub="UTC calendar days since first introduction">
        <Bars label="Issue age buckets" values={data.aging} />
      </Panel>
    </>
  );
}

/** Application Security: exploitability, vulnerability classes and triage. */
export function AppSecSections({ data }: { data: Dashboard }) {
  const exploitOrder = ["Mature", "Proof of Concept", "No Known Exploit", "No data"];
  const maturity = [...data.exploit_maturity].sort(
    (a, b) =>
      (exploitOrder.indexOf(a.name) + 1 || 99) - (exploitOrder.indexOf(b.name) + 1 || 99),
  );
  return (
    <>
      <div className="chart-grid">
        <Panel
          title="Exploit maturity"
          sub="Open findings by how weaponized a known exploit is"
        >
          <Donut
            label="Open findings by exploit maturity"
            values={maturity}
            colors={maturity.map((m) =>
              m.name === "Mature"
                ? "var(--sev-c)"
                : m.name === "Proof of Concept"
                  ? "var(--sev-h)"
                  : m.name === "No Known Exploit"
                    ? "var(--cat2)"
                    : "var(--sev-l)",
            )}
          />
        </Panel>
        <Panel title="Open findings by type" sub="Vulnerabilities, secrets and license issues">
          <Donut label="Open findings by issue type" values={data.issue_types} />
        </Panel>
      </div>
      <div className="chart-grid even">
        <Panel
          title="OWASP Top 10 (2021)"
          sub={`Mapped from each finding's CWE using OWASP's official lists; dependency and container vulnerabilities also count as A06. ${data.owasp_mapped.toLocaleString()} of ${data.metrics.open?.toLocaleString() ?? "—"} open findings map to at least one category.`}
        >
          <div className="owasp-list">
            {data.owasp.map((o) => {
              // Scale bars against code-level categories so a large A06 (every
              // SCA/container vulnerability) doesn't flatten the rest.
              const max = Math.max(
                ...data.owasp.filter((x) => !x.name.startsWith("A06")).map((x) => x.value),
                1,
              );
              const [code, ...rest] = o.name.split(" ");
              return (
                <div key={o.name} className={o.value ? "" : "zero"} title={`${o.value.toLocaleString()} open · ${o.critical_high.toLocaleString()} critical/high`}>
                  <span className="owasp-code">{code.replace(":2021", "")}</span>
                  <span className="owasp-name">
                    {rest.join(" ")}
                    {code.startsWith("A06") && o.value > 0 && (
                      <small> · all SCA & container vulnerabilities</small>
                    )}
                  </span>
                  <span className="owasp-bar">
                    <i style={{ width: Math.min(100, (o.value / max) * 100) + "%" }} />
                  </span>
                  <b>{o.value.toLocaleString()}</b>
                  <small>{o.critical_high.toLocaleString()} C+H</small>
                </div>
              );
            })}
          </div>
        </Panel>
        <Panel
          title="Top vulnerability classes (CWE)"
          sub="Open findings per weakness (CWE number below each bar) · hover for the full name"
          fill
        >
          {data.cwes.length ? (
            <Bars
              label="Top CWEs"
              values={data.cwes}
              fill
              showValues
              categoryLabel={(id) => id.replace(/^CWE-/, "")}
              barLabel={(id) => CWE_NAMES[id]?.[0] ?? ""}
              tooltipLabel={(id) => (CWE_NAMES[id] ? `${id} · ${CWE_NAMES[id][1]}` : id)}
            />
          ) : (
            <p className="empty-inline">This export has no CWE data.</p>
          )}
        </Panel>
      </div>
      <div className="chart-grid even">
        <Panel title="Introduction sources" sub="Why findings appeared in the selected period">
          <Bars label="Introduction sources" values={data.sources} />
        </Panel>
        <Panel title="Over-SLA findings by product" sub="Where the policy is being missed">
          <Bars
            label="Over SLA by product"
            horizontal
            values={data.products.map((p) => ({ name: p.name, value: p.over_sla }))}
          />
        </Panel>
      </div>
      <Panel title="Most widespread CVEs" sub="Open findings per CVE">
        <div className="two-column">
          <Ranking
            valueLabel="findings"
            empty="This export has no CVE data."
            rows={data.cves.map((c) => ({
              key: c.name,
              name: c.name,
              sub: "Open findings",
              value: c.value,
              of: data.cves[0]?.value || 1,
            }))}
          />
        </div>
      </Panel>
    </>
  );
}

/** Engineering: repositories, packages and quick-win fixes. */
export function EngineeringSections({
  data,
  onRepo,
}: {
  data: Dashboard;
  onRepo: (repo: string) => void;
}) {
  const [repoSearch, setRepoSearch] = useState("");
  const needle = repoSearch.trim().toLowerCase();
  const repos = needle
    ? data.repositories.filter((r) =>
        `${r.repo} ${r.org} ${r.branches.join(" ")}`.toLowerCase().includes(needle),
      )
    : data.repositories;
  return (
    <>
      <Panel
        title="Repositories needing attention"
        sub={`${data.repository_total.toLocaleString()} repositories with open findings · ranked by critical/high, then SLA breaches`}
      >
        <div className="table-controls">
          <input
            aria-label="Search repositories"
            placeholder="Search repository, organization or branch"
            value={repoSearch}
            onChange={(e) => setRepoSearch(e.target.value)}
          />
          {needle && (
            <button className="link-button" onClick={() => setRepoSearch("")}>
              Clear search
            </button>
          )}
        </div>
        <div className="table-scroll repo-scroll">
          <table>
            <thead>
              <tr>
                <th>Repository / target</th>
                <th>Organization</th>
                <th>Open</th>
                <th>Critical + High</th>
                <th>Over SLA</th>
                <th>Fixable</th>
                <th>Projects</th>
                <th>Branches</th>
              </tr>
            </thead>
            <tbody>
              {repos.map((r) => (
                <tr key={r.repo}>
                  <td>
                    <button className="issue-link" onClick={() => onRepo(r.repo)}>
                      {r.repo}
                    </button>
                  </td>
                  <td>{r.org}</td>
                  <td>{r.open.toLocaleString()}</td>
                  <td>{r.critical_high.toLocaleString()}</td>
                  <td className={r.over_sla ? "bad" : ""}>{r.over_sla.toLocaleString()}</td>
                  <td>
                    {r.fixable.toLocaleString()}
                    <small>{r.open ? Math.round((r.fixable / r.open) * 100) : 0}% fixable</small>
                  </td>
                  <td>{r.projects}</td>
                  <td>{r.branches.join(", ") || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!repos.length && (
            <p className="empty-inline">No repositories match “{repoSearch}”.</p>
          )}
        </div>
        <div className="table-footer">
          Showing {repos.length.toLocaleString()} of{" "}
          {data.repository_total.toLocaleString()} repositories
          {needle ? " matching" : ""}. Select a repository to filter the work list below.
        </div>
      </Panel>
      <div className="chart-grid">
        <Panel
          title="Top vulnerable packages"
          sub="Upgrading one package can clear many findings"
        >
          <div className="table-scroll repo-scroll">
            <table>
              <thead>
                <tr>
                  <th>Package</th>
                  <th>Findings</th>
                  <th>Critical + High</th>
                  <th>Repos</th>
                  <th>Fix version</th>
                </tr>
              </thead>
              <tbody>
                {data.packages.map((p) => (
                  <tr key={p.name}>
                    <td className="package-name" title={p.name}>{p.name}</td>
                    <td>{p.value.toLocaleString()}</td>
                    <td>{p.critical_high.toLocaleString()}</td>
                    <td>{p.repos}</td>
                    <td>{p.fix_version || (p.fixable ? "Available" : "—")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!data.packages.length && <p className="empty-inline">No package data in this scope.</p>}
          </div>
        </Panel>
        <Panel title="Findings by project type" sub="Language / ecosystem of the affected projects">
          <Donut label="Open findings by project type" values={data.project_types} />
        </Panel>
      </div>
      <div className="chart-grid">
        <Panel title="Open issue aging" sub="How long findings have been waiting">
          <Bars label="Issue age buckets" values={data.aging} />
        </Panel>
        <Panel title="Open findings by branch" sub="Monitored branch of each target">
          <Bars label="Open findings by branch" horizontal values={data.branches} />
        </Panel>
      </div>
    </>
  );
}
