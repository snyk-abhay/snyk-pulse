# Metric dictionary — utility v0.2

## Contract

One normalized record is an issue occurrence in a scope, not a globally unique CVE. Identity includes org/project and `ASSET_FINDING_ID` or `ISSUE_URL`; otherwise it includes project, problem, product, package, source location and target ref. Exact duplicate rows are deduplicated. Conflicting rows sharing that identity fail the entire import rather than silently deleting occurrences. The project-ID fallback still requires validation against representative exports.

`FIRST_INTRODUCED`, `LAST_RESOLVED`, `LAST_INTRODUCED` and `LAST_IGNORED` are parsed as UTC; naive timestamps are assumed UTC. The selected period includes both boundary dates. Weekly buckets begin at the selected start date; the last bucket may be shorter. Resolution duration is elapsed fractional days; SLA uses **UTC calendar days**. The deadline day is within SLA; breach begins when age > policy days. This calendar-day choice needs customer approval before production.

Every import is a **complete scoped snapshot**, not an incremental update. Issue, project and group deletion markers exclude rows. Missing issue/project deletion columns produce a quality warning. Missing required identity/date/status fields reject the import; malformed dates never become zeros. Active snapshot is the most recently imported file, not the greatest snapshot date.

Latest lifecycle fields do not preserve every reopen, fix, or ignore event. Flow metrics, period comparisons and MTTR are provisional approximations from these latest fields. An issue resolved and then reopened is currently open, and is excluded from F1 even if its earlier resolution was in the period. No historical backlog is reconstructed from current status.

## Catalog and implementation status

| ID | Metric | Utility behavior |
|---|---|---|
| N1 | New | Count FIRST_INTRODUCED in inclusive period. |
| N2 | New critical/high | N1 restricted by severity. |
| N3 | Reintroduced | Last introduction in period after last resolution; lower bound from available latest timestamps. |
| N4 | Introduction source | N1 grouped by INTRODUCTION_CATEGORY; missing values are Unknown. |
| N5 | New/project | Unavailable until active inventory denominator exists. |
| F1 | Fixed | Currently Resolved AND LAST_RESOLVED in period. |
| F2 | Fixed critical/high | F1 restricted by severity. |
| F3 | Net remediation | F1 − N1, positive is favorable; not a measured change in historical backlog. |
| F4 | Fix rate | Unavailable: needs true open-at-start snapshot. |
| F5 | Burn-down ratio | F1 / N1; unavailable when N1=0. |
| F6 | Fixed by product | F1 grouped by product, exposed in API. |
| B1 | Open | Current Open records in active snapshot. |
| B2 | Severity backlog | B1 grouped by severity; critical/high headline. |
| B3 | Fixable open | Fixable label OR fixed-in-available flag. Unknown if any scoped open row lacks determinable fixability. |
| B4 | Exploitable open | Mature or PoC; unknown if exploit maturity is missing. |
| B5 | Reachable open | Reachability equals reachable; unknown if missing. |
| B6 | Issue density | Unavailable until a complete project denominator is defined. |
| B7 | Top CVE/CWE/package | Columns retained; distinct affected-project ranking is pending. |
| T1 | MTTR | Mean elapsed fractional days, first introduction to last resolution, for F1. Critical MTTR filters criticals. |
| T2 | Median/P90 | Median and linearly interpolated 90th percentile over F1 durations. |
| T3 | Mean open age | UTC calendar-day difference from snapshot date to first introduction. |
| T4 | Aging | Inclusive buckets: 0–30, 31–90, 91–180, 181+. |
| T5 | SLA compliance | Fixed within severity SLA / F1 × 100; unavailable without fixes. |
| T6 | Over SLA | Open age > severity SLA. |
| T7 | Due in 7 days | Open and remaining calendar days in [0,7]. |
| R1 | Ignored | Currently Ignored snapshot rows. |
| R2 | Ignore rate | LAST_IGNORED in period / (F1 + LAST_IGNORED in period) × 100. Latest timestamps can miss earlier ignore events. |
| R3 | Critical ignores | Count available in API; audit reason/approver pending. |
| R4 | Risk score | Unavailable until versioned risk model approved and inputs validated. |
| C1 | Projects monitored | Unavailable without inventory, including zero-issue projects. |
| C2 | Product coverage | Unavailable without target/project inventory. Never inferred from issue-bearing projects. |
| C3 | Stale projects | Unavailable without usage/inventory. |
| C4 | Scans run | Unavailable without usage. |
| C5 | Jira linkage | Critical/high open with explicit Jira boolean / critical/high open. Unknown if any required flags missing or denominator=0. |
| P1 | PR-check pass rate | Unavailable without PR checks. |
| P2 | Issues prevented | Unavailable without prevention events. |

Unavailable values are JSON `null`, a dash in the UI, and `Unavailable` in KPI CSV. Counts over an empty known population are zero. Optional fields with unknown data must not silently reduce counts. The UI shows selected headline/analytical metrics; additional computed values are available in API and KPI CSV. All 36 production metrics are not yet implemented.

## Filtering and reports

API scope filters: Group display value, org ID, project ID, product, severity. The UI exposes organization/product/severity. Organization rankings combine all projects under the same organization ID. Display-name group filtering is a prototype limitation; production must use immutable group IDs.

Issue-table filters (all/overdue/fixable) affect only the displayed first 250 rows. The clearly labeled full CSV includes all open rows in global scope; the report library has a separate SLA-breach CSV. KPI CSV records the scope, selected period, snapshot date and current SLA policy.

SLA changes apply retroactively to the active snapshot and report calculations. Policy effective-date history, frozen reports, historical snapshot queries and historical stock deltas are future work. Data is session-only; no historical imports are stored. Additional datasets can power custom metrics through the declarative extension mechanism; built-in unavailable metrics are not automatically replaced.
