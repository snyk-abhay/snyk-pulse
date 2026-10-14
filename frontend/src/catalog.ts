export const catalog: Record<
  string,
  { label: string; detail: string; unit?: string }
> = {
  open: { label: "Open issues", detail: "Open at the snapshot date." },
  open_critical_high: {
    label: "Open Critical + High",
    detail: "Open critical and high findings at the snapshot date.",
  },
  sla_compliance: {
    label: "SLA compliance",
    unit: "%",
    detail: "Resolved within severity SLA ÷ resolved in the selected period.",
  },
  mttr_critical_days: {
    label: "MTTR · Critical",
    unit: "d",
    detail:
      "Mean elapsed days from first introduction to latest resolution for criticals fixed in the period.",
  },
  mttr_days: {
    label: "Mean time to resolve",
    unit: "d",
    detail: "Mean elapsed days to resolve findings fixed in the period.",
  },
  exploitable_open: {
    label: "Exploitable open",
    detail:
      "Open findings with mature or proof-of-concept exploits. Requires exploit maturity data.",
  },
  reachable_open: {
    label: "Reachable open",
    detail:
      "Open findings marked reachable; unavailable if reachability data is incomplete.",
  },
  new: {
    label: "Introduced",
    detail: "Findings first introduced during the selected period.",
  },
  new_critical_high: {
    label: "Introduced Critical + High",
    detail: "Critical and high findings first introduced in the period.",
  },
  fixed: {
    label: "Fixed",
    detail:
      "Currently resolved findings whose latest resolution is in the period.",
  },
  fixed_critical_high: {
    label: "Fixed Critical + High",
    detail: "Critical and high findings resolved during the period.",
  },
  net_change: {
    label: "Net remediation",
    detail:
      "Fixed − introduced. Positive means fixes exceeded new findings; this is not historical backlog change.",
  },
  burn_down_ratio: {
    label: "Burn-down ratio",
    unit: "×",
    detail:
      "Fixed ÷ introduced in the period; unavailable when none were introduced.",
  },
  fixable_open: {
    label: "Fixable open",
    detail:
      "Open findings with a remediation available. Requires fixability data.",
  },
  over_sla: {
    label: "Open over SLA",
    detail:
      "Open findings older than their severity deadline in UTC calendar days.",
  },
  due_7_days: {
    label: "Due in ≤7 days",
    detail:
      "Open findings due from the snapshot date through the next seven days.",
  },
  median_fix_days: {
    label: "Median time to fix",
    unit: "d",
    detail:
      "50th percentile resolution duration for findings fixed in the period.",
  },
  p90_fix_days: {
    label: "P90 time to fix",
    unit: "d",
    detail:
      "90th percentile resolution duration for findings fixed in the period.",
  },
  mean_open_age_days: {
    label: "Mean open age",
    unit: "d",
    detail: "Mean UTC calendar age of open findings at the snapshot date.",
  },
  ignored: { label: "Ignored issues", detail: "Currently ignored findings." },
  critical_ignored: {
    label: "Critical ignored",
    detail: "Currently ignored critical findings.",
  },
  ignore_rate: {
    label: "Ignore rate",
    unit: "%",
    detail: "Ignored events ÷ (resolved + ignored events) in the period.",
  },
  jira_linkage: {
    label: "Jira linkage",
    unit: "%",
    detail:
      "Open critical/high findings linked to Jira ÷ open critical/high findings.",
  },
  reintroduced: {
    label: "Reintroduced",
    detail:
      "Findings last introduced after a prior resolution, during the period.",
  },
  risk_score: {
    label: "Risk score",
    detail: "Unavailable: needs approved risk weights and a defined model.",
  },
  product_coverage: {
    label: "Product coverage",
    unit: "%",
    detail: "Unavailable: needs a complete eligible project inventory.",
  },
  fix_rate: {
    label: "Fix rate",
    unit: "%",
    detail: "Unavailable: needs historical opening backlog.",
  },
  projects_monitored: {
    label: "Projects monitored",
    detail:
      "Unavailable from issue rows: projects with no issues would be missing. Add an inventory metric.",
  },
  stale_projects: {
    label: "Stale projects",
    detail: "Needs project inventory and last-tested timestamps.",
  },
  scans_run: {
    label: "Scans run",
    detail: "Add a period metric from a usage dataset.",
  },
  pr_pass_rate: {
    label: "PR pass rate",
    unit: "%",
    detail: "Add a percentage metric from the PR checks dataset.",
  },
  issues_prevented: {
    label: "Issues prevented",
    detail: "Add a count metric from the prevention events dataset.",
  },
  issue_density: {
    label: "Issue density",
    detail: "Needs an eligible project inventory denominator.",
  },
  exploitable_reachable_open: {
    label: "Exploitable + reachable",
    detail:
      "Open findings with a known exploit whose vulnerable code is reachable. Highest-priority triage set.",
  },
  mature_exploit_open: {
    label: "Mature exploits open",
    detail: "Open findings whose exploit maturity is Mature (weaponized).",
  },
  kev_open: {
    label: "CISA KEV open",
    detail:
      "Open findings on CISA's Known Exploited Vulnerabilities list, from the export's IS_CISA_KEV column. Shows — when Snyk leaves that column empty.",
  },
  secrets_open: {
    label: "Open secrets",
    detail: "Hard-coded credentials and keys currently open. Rotate, then remove.",
  },
  affected_repos: {
    label: "Affected repositories",
    detail: "Repositories / targets with at least one open finding.",
  },
  repos_over_sla: {
    label: "Repos breaching SLA",
    detail: "Repositories with at least one open finding past its severity deadline.",
  },
  fixable_critical_high: {
    label: "Fixable Critical + High",
    detail:
      "Open critical and high findings with an upgrade or patch available. Fastest risk reduction.",
  },
  vulnerable_packages: {
    label: "Vulnerable packages",
    detail: "Distinct package versions with open findings.",
  },
  new_per_project: {
    label: "New per project",
    detail: "Needs an eligible project inventory denominator.",
  },
};
// Each dashboard answers a different question for a different audience.
export const personaMetrics: Record<string, string[]> = {
  // Leadership: how much risk, is it shrinking, are we meeting policy?
  CISO: [
    "open_critical_high",
    "exploitable_open",
    "sla_compliance",
    "mttr_critical_days",
    "net_change",
    "critical_ignored",
  ],
  // Security team: what is most dangerous and what to triage first.
  AppSec: [
    "exploitable_reachable_open",
    "mature_exploit_open",
    "secrets_open",
    "over_sla",
    "due_7_days",
    "kev_open",
  ],
  // Developers: which repositories need work and what is quick to fix.
  Engineering: [
    "affected_repos",
    "repos_over_sla",
    "fixable_critical_high",
    "median_fix_days",
    "new",
    "mean_open_age_days",
  ],
  // Drill-down for one organization (reached from the CISO leaderboard).
  Organization: [
    "open_critical_high",
    "over_sla",
    "due_7_days",
    "fixable_open",
    "mttr_days",
    "sla_compliance",
  ],
};
export const personaQuestion: Record<string, string> = {
  CISO: "Overall risk posture, trend and policy compliance across every organization.",
  AppSec: "Exploitability, vulnerability classes and the findings to triage first.",
  Engineering: "Repositories, packages and quick-win fixes for development teams.",
  Organization: "Scorecard for the selected organization.",
};
