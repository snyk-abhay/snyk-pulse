# Snyk Pulse user guide

Snyk Pulse turns a Snyk issues export into security dashboards and reports. You run one Node command, and your browser opens a private local dashboard. You can also run it from a scheduler to write CSV reports and exit.

This guide covers installation, first run, every command-line option, scheduled runs, the data Pulse can pull, the metrics it calculates, extensions and the maintainer build. For metric definitions in depth, see [METRICS.md](METRICS.md). For custom datasets and metrics, see [EXTENSIONS.md](EXTENSIONS.md).

**Contents**

1. [Before you start](#1-before-you-start)
2. [Add Pulse to your machine](#2-add-pulse-to-your-machine)
3. [Choose a Snyk token](#3-choose-a-snyk-token)
4. [Run Pulse interactively](#4-run-pulse-interactively)
5. [Use the dashboards](#5-use-the-dashboards)
6. [Export reports](#6-export-reports)
7. [Run Pulse from a scheduler](#7-run-pulse-from-a-scheduler)
8. [Command-line reference](#8-command-line-reference)
9. [What data Pulse can pull](#9-what-data-pulse-can-pull)
10. [Metrics Pulse calculates](#10-metrics-pulse-calculates)
11. [Add datasets, metrics and an SLA policy](#11-add-datasets-metrics-and-an-sla-policy)
12. [Build and package Pulse (maintainers)](#12-build-and-package-pulse-maintainers)
13. [Sessions, ports and stopping Pulse](#13-sessions-ports-and-stopping-pulse)
14. [Troubleshooting](#14-troubleshooting)
15. [How Pulse handles data and credentials](#15-how-pulse-handles-data-and-credentials)

---

## 1. Before you start

| You need | Details |
| --- | --- |
| Node.js 22 or newer | Check with `node --version`. Nothing else is required: no `npm install`, Python, database, Docker or build step. |
| One data source | A Snyk issues CSV export, **or** a Snyk API token with Export API access. The `--demo` option works without either. |
| For API pulls | Your Snyk region and a group or organization to report on. The setup screen can list the groups and organizations your token can see. |
| A browser | Pulse opens the dashboard automatically. Use `--no-open` to print the link instead. |

## 2. Add Pulse to your machine

Choose one of these options.

**Option A: from this repository**

```sh
cd snyk-pulse
node pulse.mjs --help
```

**Option B: from the release archive**

```sh
tar -xzf snyk-pulse-utility.tgz        # creates ./snyk-pulse/
node pulse.mjs --help
```

**Option C (optional): add a `snyk-pulse` command**

```sh
npm install -g ./snyk-pulse
snyk-pulse --help
```

The global command links to that folder, so leave the folder in place. The rest of this guide uses `node pulse.mjs`; with option C, replace it with `snyk-pulse`.

**Check that it works.** This command writes sample reports from synthetic data and exits:

```sh
node pulse.mjs --demo --out ./pulse-reports --no-serve
```

You should see `Reports written to …/pulse-reports`, which contains `metrics.csv` and `open-issues.csv`.

## 3. Choose a Snyk token

| Token | Where to get it | Use it for |
| --- | --- | --- |
| Personal access token (PAT) | **My Profile → Personal access tokens** | Ad hoc reports with your own permissions |
| Legacy personal API token | **My Profile → API key → Click to show** (if available) | Ad hoc reports with your own permissions |
| Group service-account token | **Group → Settings → Service accounts** (Group admin) | Scheduled group reporting; its role controls access |
| Organization service-account token | **Organization → Settings → Service accounts** | Scheduled reporting for one organization only |

- Use a **service account** for scheduled runs.
- Paste only the token value, without an `Authorization` or `token` prefix.
- An OAuth service account needs an issued access token. A client ID or client secret alone does not work.
- Pass the token through the `SNYK_TOKEN` environment variable rather than `--api-key`, which leaves it in shell history and process listings.
- Token validation confirms identity only. Your Snyk plan and the token's role must also permit Export API access to the chosen scope and datasets.

## 4. Run Pulse interactively

### Step 1: start Pulse

```sh
node pulse.mjs
```

Pulse starts on `http://127.0.0.1:8780` (or the last `--port` you used), prints a one-time launch link and opens it in your browser. Always open that **launch link**; the bare port returns "Open the launch URL printed in your terminal."

To skip the setup screen, give Pulse the input directly:

```sh
node pulse.mjs --csv ./issues.csv
SNYK_TOKEN=... node pulse.mjs --org YOUR_ORG_UUID --region eu
SNYK_TOKEN=... node pulse.mjs --group YOUR_GROUP_UUID --datasets issues,usage --region eu
node pulse.mjs --demo
```

### Step 2: complete the setup screen

The setup screen has four steps: **Connect → Scope → SLA policy → Review**.

**Connect**

- **CSV file:** choose a UTF-8 CSV of up to 50 MiB and 100,000 rows.
- **Snyk API:** choose your region, paste the token, then click **Validate token & load scopes**. Pulse checks the token against `/rest/self`, then lists the groups and organizations it can see.

| Region | API host |
| --- | --- |
| US-01 (`us`, default) | `api.snyk.io` |
| US-02 (`us02`) | `api.us.snyk.io` |
| EU (`eu`) | `api.eu.snyk.io` |
| AU (`au`) | `api.au.snyk.io` |
| US government (`gov`) | `api.snykgov.io` |

**Scope**

- **CSV:** choose the dataset (usually **Issues**) and the **Snapshot date (UTC)**, meaning the date the export was taken.
- **API:**
  - Choose **Organization** or **Group**. You can filter organizations by group.
  - If your token cannot list scopes, click **Enter a scope UUID instead**.
  - Tick the datasets to pull. **Issues** is required for the dashboards.
  - To continue an earlier export, open **Resume an export from a previous session**, tick **Use an existing export ID**, paste the ID and choose its single dataset.

**SLA policy**

Set the days allowed to fix each severity. The defaults are critical 15, high 30, medium 90 and low 180. Ages count UTC calendar days from first introduction, and a finding is overdue on the day after its deadline.

**Review**

- API pulls show progress for each dataset and export ID.
- **Cancel pull** stops the local work.
- If retries run out, **Resume existing export** continues the same export without submitting a new one.
- Open the dashboards when loading finishes.

### Step 3: stop Pulse

Press **Ctrl+C** in the terminal, or run `node pulse.mjs --stop` from another terminal. Loaded data and tokens disappear when Pulse stops, so download what you need first.

## 5. Use the dashboards

The left navigation has four sections:

| Section | Page | What it shows |
| --- | --- | --- |
| Dashboards | **CISO dashboard** | Leadership view. KPIs: open critical+high, exploitable open, SLA compliance, critical MTTR, net remediation, critical ignored. Charts: risk trend, severity backlog, risk by product, organizations over SLA, aging. **Prepare board report** lives here. |
| | **Application security** | Security triage view. KPIs: exploitable + reachable, mature exploits, open secrets, over SLA, due ≤7 days, CISA KEV (when exported). Charts: exploit maturity, issue type, top CWEs, most widespread CVEs, introduction sources, over-SLA by product. |
| | **Engineering** | Repository view for developers. KPIs: affected repositories, repos breaching SLA, fixable critical+high, median time to fix, introduced, mean open age. Repository leaderboard (click a repo to filter the work list), top vulnerable packages with fix versions, project types, aging, branches. |
| | **Organization scorecard** | One organization's KPIs; open it by selecting an organization on the CISO dashboard. |
| Explore | **Metric explorer** | Any metric grouped by organization, product or severity |
| | **Metric dictionary** | A searchable definition of every number |
| Reports | **Report library** | Ready-made reports and CSV downloads ([section 6](#6-export-reports)) |
| | **Report builder** | Assemble a report, then print or save it as PDF |
| Configure | **Data & metrics** | Loaded datasets, column lists, CSV downloads, custom metrics and dataset registration |
| | **SLA policy** | Change the severity deadlines; every view recalculates |

\* Always shows "Unavailable" until the inputs it needs exist ([section 10](#10-metrics-pulse-calculates)).

All dashboards also show weekly introduced-vs-fixed trends, backlog by severity, aging buckets, organization priorities and a remediation work list. Organization is the reporting unit: findings from its projects are grouped by organization ID.

**Filters.** Use **Organization**, **Product** and **Severity** together with **Period start** and **Period end**. The period defaults to the 90 days ending on the snapshot date, and you can choose from 1 to 731 days. Backlog and aging always use the snapshot date. The period controls introduction and fix activity.

**Other controls.** Switch between dark and light themes in the header. "Unavailable" or a dash means Pulse lacks the data; it never shows a missing value as zero.

## 6. Export reports

The **Report library** uses your current filters, period and SLA policy:

| Report | Output |
| --- | --- |
| Monthly CISO posture | Report builder: KPIs, weekly flow, aging and a remediation list |
| Executive board summary | Report builder: KPIs, trend and aging |
| SLA breach report | CSV of every open finding past its deadline |
| Open remediation queue | CSV of all open findings with fix versions |
| Metric data export | CSV of all built-in and custom metric values, with scope |
| Organization scorecard | Report builder for the organization you select in the filters |

In the **Report builder**, set a title and tick the sections (KPIs, trend, aging, table). Then click **Print / save PDF** or **Download metric CSV**. PDFs come from your browser's print dialog. PowerPoint export is not available.

**Data & metrics** also downloads any loaded dataset as CSV (`pulse-<dataset>.csv`).

### 6.1 Generate a full report (PDF, HTML, CSV, JSON)

**Reports → Generate report** runs the Snyk report generator from the dashboard. Pulse ships its own copy in `vendor/snyk-auto-report.mjs` (a single bundled file built from `snyk_report/`), so it works wherever the `snyk-pulse` folder is copied. It produces a complete, shareable report: cover page, report details, executive summary, findings index, findings register, per-finding details and a methodology appendix.

1. **Data and period.** *Loaded data* uses whatever is in Pulse now — an imported CSV or an earlier API pull — so it is instant and makes no Snyk call. *Live from Snyk* runs a fresh Export API pull with the saved token and scope (minutes; counts toward Snyk's 20 exports per hour). **Findings first introduced** limits either source to a period: last 7/14/30/90 days, 6 months, 365 days, 2 years, all history, *From a date onwards*, or a *Custom date range* with From and To date pickers (inclusive). Live reports send it to the Export API; loaded data is filtered on `FIRST_INTRODUCED`.
2. **What to include.** Severity, status and product filters, the number of detailed findings, and the findings-register row limit (keep it to a few hundred for a manageable PDF).
3. **Cover page.** Title, subtitle, prepared for/by and classification.
4. **Formats.** PDF needs Google Chrome, Chromium or Microsoft Edge installed (or `CHROME_PATH`).

Reports run in the background with live progress and can be cancelled. Finished reports are saved in `~/.snyk-pulse/reports/` and listed with download links; HTML opens in a new tab. To use a different generator build, start Pulse with `--report-tool /path/to/snyk-auto-report.mjs` or set `PULSE_REPORT_TOOL`. The Snyk token is passed to the generator in its environment only, never on the command line.

## 7. Run Pulse from a scheduler

Headless mode loads data, writes two CSV reports, then exits. It doesn't start the dashboard, and it doesn't stop a dashboard you already have open.

### 7.1 The command

```sh
# From an API pull (token in the environment)
SNYK_TOKEN=... node pulse.mjs --group YOUR_GROUP_UUID --region eu --out ./reports --no-serve

# From a CSV export
node pulse.mjs --csv ./issues.csv --as-of 2026-10-09 --out ./reports --no-serve
```

`--out` and `--no-serve` are both required for a headless run. The input must include the **issues** dataset.

### 7.2 Scheduler options

| Option | Required | Default | Notes |
| --- | --- | --- | --- |
| `--out DIR` | Yes | — | Created if missing, with owner-only permissions. Overwrites the two report files on every run. |
| `--no-serve` | Yes | off | Exit after writing reports. Requires `--out`. |
| `SNYK_TOKEN` (env) or `--api-key` | For API input | — | Prefer the environment variable. `--api-key` takes precedence if both are set. |
| `--org UUID` or `--group UUID` | For API input | — | Exactly one scope per run. |
| `--region` | No | `us` | `us`, `us01`, `us02`, `eu`, `au` or `gov`. It must match the token's region. |
| `--datasets LIST` | No | `issues` | Comma-separated, up to 20. Must include `issues` for the reports. |
| `--from ISO_DATE` | No | `1970-01-01` | Export lower bound. Leave the default for a complete backlog ([warning below](#73-what-each-run-does)). |
| `--export-id UUID` | No | — | Download an existing export instead of submitting a new one. Allows one dataset only. |
| `--csv FILE` | For CSV input | — | Cannot be combined with `--org` or `--group`. |
| `--dataset NAME=FILE` | No | — | Extra local datasets for custom metrics. Repeatable. |
| `--as-of YYYY-MM-DD` | No | today (UTC) | Snapshot date for CSV input only. API pulls always use today. |
| `--sla FILE` | No | 15/30/90/180 | SLA policy for `over_sla`, `sla_compliance` and `due_7_days`. |
| `--metrics FILE` | No | — | Adds custom metrics to `metrics.csv` as `custom:<id>` rows. |
| `--registry FILE` | No | — | Registers extra Export API datasets you name in `--datasets`. |

### 7.3 What each run does

1. Validates the token against `/rest/self`, retrying once with the `bearer` scheme only after a 401 response.
2. Submits one Snyk export per dataset, polls the job every 5–30 seconds, then downloads and checks the files.
3. Calculates metrics for **the 90 days ending today (UTC)** across the **whole pulled scope**, with no filters. The command line cannot change this period or apply filters.
4. Writes `metrics.csv` and `open-issues.csv` to `--out`, then exits.

Things to plan for:

- **Rate limits:** Snyk allows about 20 export submissions per hour, and each run uses one per dataset. Daily or weekly schedules are fine.
- **Time limit:** a pull can run for up to 30 minutes. Pulse retries interrupted downloads and status checks three times, but never resubmits an export automatically.
- **Narrow `--from`:** findings introduced before that date are missing, so the backlog is undercounted.
- **History:** each run overwrites the previous files. Write to a dated folder to keep a history ([examples below](#75-schedule-it)).

### 7.4 Output files and exit codes

**`metrics.csv`** has one row per metric:

| Column | Meaning |
| --- | --- |
| `metric` | Metric name ([section 10](#10-metrics-pulse-calculates)); custom metrics appear as `custom:<id>` |
| `value` | Number, or `Unavailable` |
| `period_start`, `period_end` | Activity period (inclusive) |
| `snapshot_date` | The date backlog and aging are measured on |
| `scope` | JSON of the filters (all empty in scheduled runs) |
| `sla_policy` | JSON of the SLA days used |

**`open-issues.csv`** has one row per open finding, most urgent first:

`snapshot_date, problem_id, title, org, project, product, severity, status, age_days, sla_days, over_sla, fixable, fix_version, package`

Cells that start with `=`, `+`, `-` or `@` get a leading apostrophe so that spreadsheets don't run them as formulas.

**Exit codes:** `0` means success. `1` means an error, with the message on stderr prefixed `Snyk Pulse:` and the token redacted.

### 7.5 Schedule it

Schedulers start with a minimal `PATH`, so use the absolute path to Node. Find it with `which node` (macOS/Linux) or `where node` (Windows).

On macOS, cron and launchd jobs cannot read `~/Documents`, `~/Desktop` or `~/Downloads` by default. Either keep Pulse and the reports folder somewhere else, such as `~/tools/snyk-pulse`, or grant Full Disk Access to `/usr/sbin/cron` (or `/bin/sh`, for launchd) in **System Settings → Privacy & Security**.

**macOS / Linux: wrapper script.** Save this as `run-pulse.sh`, then run `chmod 700 run-pulse.sh`:

```sh
#!/bin/sh
set -eu
# A file containing one line, SNYK_TOKEN=..., readable only by you (chmod 600).
. "$HOME/.config/snyk-pulse/env"
export SNYK_TOKEN
cd /path/to/snyk-scripts
mkdir -p ./pulse-reports
/usr/local/bin/node pulse.mjs \
  --group YOUR_GROUP_UUID --region eu \
  --sla ./sla.json \
  --out "./pulse-reports/$(date -u +%Y-%m-%d)" --no-serve \
  >> ./pulse-reports/pulse.log 2>&1
```

**cron** (Mondays at 06:00). Edit with `crontab -e`:

```text
0 6 * * 1 /path/to/run-pulse.sh
```

**macOS launchd** (the native alternative to cron). Save as `~/Library/LaunchAgents/com.example.snyk-pulse.plist`, then run `launchctl load ~/Library/LaunchAgents/com.example.snyk-pulse.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.example.snyk-pulse</string>
  <key>ProgramArguments</key><array><string>/path/to/run-pulse.sh</string></array>
  <key>StartCalendarInterval</key>
  <dict><key>Weekday</key><integer>1</integer><key>Hour</key><integer>6</integer><key>Minute</key><integer>0</integer></dict>
</dict>
</plist>
```

**Windows Task Scheduler.** First set `SNYK_TOKEN` as a user environment variable for the account that runs the task. Then save this as `run-pulse.cmd`:

```bat
@echo off
cd /d C:\tools
for /f %%d in ('powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd"') do set D=%%d
"C:\Program Files\nodejs\node.exe" snyk-pulse\pulse.mjs --org YOUR_ORG_UUID --region eu --out reports\%D% --no-serve >> reports\pulse.log 2>&1
```

Create the task:

```bat
schtasks /Create /TN "Snyk Pulse weekly" /SC WEEKLY /D MON /ST 06:00 /TR "C:\tools\run-pulse.cmd"
```

**CI pipeline (GitLab example).** Store `SNYK_TOKEN` as a masked CI/CD variable and run the job from a pipeline schedule. The artifacts contain finding details, so restrict who can download them.

```yaml
pulse-report:
  image: node:22
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
  script:
    - node pulse.mjs --group "$SNYK_GROUP_ID" --region eu --out "reports/$(date -u +%F)" --no-serve
  artifacts:
    paths: [reports/]
    expire_in: 90 days
```

Pulse does not send email or Slack messages. Use your scheduler or pipeline to deliver the files.

## 8. Command-line reference

```text
node pulse.mjs [options]
```

Unknown options and positional arguments are rejected.

**Inputs**

| Option | Default | Description |
| --- | --- | --- |
| `--csv FILE` | — | A complete, scoped issues CSV. Same as `--dataset issues=FILE`. |
| `--dataset NAME=FILE` | — | Load a CSV as a registered dataset. Repeatable; each name once. |
| `--api-key TOKEN` | `SNYK_TOKEN` | Snyk token. Prefer the environment variable. |
| `--org UUID` | — | Pull one organization. |
| `--group UUID` | — | Pull one group. Use either `--org` or `--group`, not both. |
| `--region R` | `us` | `us`/`us01`, `us02`, `eu`, `au`, `gov`. Case- and hyphen-insensitive, so `US-02` works. |
| `--datasets LIST` | `issues` | API datasets to pull, comma-separated, distinct, up to 20 ([section 9](#9-what-data-pulse-can-pull)). |
| `--from ISO_DATE` | `1970-01-01T00:00:00Z` | Export lower bound, applied to each dataset's date filter. |
| `--export-id UUID` | — | Resume an existing export. Requires exactly one dataset and the original scope and region. |
| `--as-of YYYY-MM-DD` | today (UTC) | Snapshot date for CSV input. Cannot be in the future. |
| `--demo` | off | Load 540 synthetic findings. Cannot be combined with other inputs. |

**Extensions**

| Option | Description |
| --- | --- |
| `--metrics FILE` | JSON array of up to 100 custom metric definitions (file maximum 1 MiB) |
| `--registry FILE` | JSON array of additional Export API dataset definitions |
| `--sla FILE` | JSON severity-to-days policy, for example `{"critical":15,"high":30,"medium":90,"low":180}`. Integers from 1 to 3650; omitted severities keep their defaults. |

**Output and runtime**

| Option | Default | Description |
| --- | --- | --- |
| `--out DIR` | — | Write `metrics.csv` and `open-issues.csv`. Without `--no-serve`, the dashboard still starts afterwards. |
| `--no-serve` | off | Exit after writing `--out` (headless mode) |
| `--no-open` | off | Print the launch link without opening a browser |
| `--port N` | `8780` | Fixed loopback port, 1–65535. Remembered for later launches. Pulse never picks a random port. |
| `--stop` | — | Stop your running Pulse instances and exit |
| `--help`, `-h` | — | Show usage |

**Environment variables**

| Variable | Purpose |
| --- | --- |
| `SNYK_TOKEN` | Snyk token, used when `--api-key` is absent |
| `NODE_EXTRA_CA_CERTS` | Path to your company's CA bundle, for TLS-inspecting proxies. Certificate checks stay enabled. |

**Rules**

- `--no-serve` requires `--out`.
- `--out` requires issues data.
- `--csv` cannot be combined with `--org` or `--group`.
- `--demo` cannot be combined with any other input.

## 9. What data Pulse can pull

### 9.1 Snyk Export API datasets

| Dataset (`--datasets` name) | Label | `--from` filters on | Built-in use |
| --- | --- | --- | --- |
| `issues` | Issues | introduced date | Powers every dashboard, report and built-in metric |
| `usage` | Usage events | updated date | Loaded, viewable and downloadable; use custom metrics |
| `pr_checks` | PR checks | updated date | Same as above |
| `pr_checks_project_adoption` | PR checks · project adoption | updated date | Same as above |
| `pr_checks_integration_adoption` | PR checks · integration adoption | updated date | Same as above |
| `prevention_events` | Prevention events | event date | Same as above |

- Pulse defines no built-in metrics for the five non-issue datasets. After loading one, open **Data & metrics → Available columns** to see its real columns, then write custom metrics ([section 11](#11-add-datasets-metrics-and-an-sla-policy)).
- Each dataset can be at most 50 MiB and 100,000 rows, including all of its export parts combined. Compressed (gzip) export files are supported.
- Other Export API datasets can be added with `--registry`. Availability depends on your Snyk plan and the token's permissions.

### 9.2 Issues CSV columns

Pulse normalizes headers by trimming them, converting to uppercase and replacing spaces with underscores, so `Issue Severity` becomes `ISSUE_SEVERITY`. Empty, `null`, `none` and `n/a` count as blank.

| Column | Required | Used for |
| --- | --- | --- |
| `PROBLEM_ID` | **Yes** | Finding identity; title fallback |
| `ORG_PUBLIC_ID` | **Yes** | Organization filter and identity |
| `ISSUE_SEVERITY` | **Yes** | Critical, High, Medium or Low |
| `ISSUE_STATUS` | **Yes** | Open, Resolved or Ignored |
| `FIRST_INTRODUCED` | **Yes** | Age, introduced counts, MTTR |
| `LAST_RESOLVED` | If Resolved | Fixed counts, MTTR, SLA compliance |
| `LAST_IGNORED` | If Ignored | Ignore rate |
| `PROJECT_PUBLIC_ID`, `ASSET_FINDING_ID`, `ISSUE_URL` | At least one | Stable identity and deduplication. Include `PROJECT_PUBLIC_ID` and `ASSET_FINDING_ID` when available. |
| `LAST_INTRODUCED` | No | Reintroduced count |
| `PROBLEM_TITLE` | No | Finding title |
| `ORG_DISPLAY_NAME` / `ORG_NAME` | No | Organization label |
| `GROUP_DISPLAY_NAME` / `GROUP_PUBLIC_ID` | No | Group label |
| `PROJECT_NAME` | No | Project label |
| `PRODUCT_NAME` | No | Product filter, fixed-by-product |
| `COMPUTED_FIXABILITY`, `FIXED_IN_AVAILABLE` | No | Fixable open |
| `EXPLOIT_MATURITY` | No | Exploitable open (Mature or PoC) |
| `REACHABILITY` | No | Reachable open |
| `HAS_JIRA_ISSUE_ASSIGNED` | No | Jira linkage |
| `INTRODUCTION_CATEGORY` | No | Introduction source |
| `FIXED_IN_VERSION`, `PACKAGE_NAME_AND_VERSION`, `CVE`, `CWE` | No | Detail columns |
| `FILE_PATH`, `CODE_REGION`, `PROJECT_TARGET_REF` | No | Identity when no finding ID or URL exists |
| `ISSUE_DELETED_AT`, `PROJECT_DELETED_AT`, `GROUP_DELETED_AT` | Recommended | Rows with a value are excluded. Missing columns produce a warning. |

**Validation rules.** Any of these rejects the whole import, and the previously loaded data stays in place:

- A missing required column or value.
- An unknown severity or status.
- A non-ISO date.
- A lifecycle date after the snapshot date or before `FIRST_INTRODUCED`.
- Two different rows that share a finding identity.

Dates without a time zone are treated as UTC. Identical duplicate rows are merged.

**Other datasets** keep their columns and rows as exported, for use by custom metrics.

## 10. Metrics Pulse calculates

The "Period" column marks metrics that count activity inside the selected period. All others measure the snapshot. These names appear in `metrics.csv` and the dashboards. Full definitions are in [METRICS.md](METRICS.md).

| `metric` | Period | Meaning | Unavailable when |
| --- | --- | --- | --- |
| `new` | ✓ | Findings first introduced | — |
| `new_critical_high` | ✓ | Introduced, critical or high | — |
| `reintroduced` | ✓ | Introduced again after a resolution | — |
| `fixed` | ✓ | Currently resolved, resolved in the period | — |
| `fixed_critical_high` | ✓ | Fixed, critical or high | — |
| `net_change` | ✓ | Fixed − introduced (positive is good) | — |
| `burn_down_ratio` | ✓ | Fixed ÷ introduced | Nothing was introduced |
| `open` | | Open findings | — |
| `open_critical_high` | | Open critical or high | — |
| `fixable_open` | | Open with a fix available | Any open row lacks fixability data |
| `exploitable_open` | | Open with a Mature or PoC exploit | Any open row lacks exploit maturity |
| `reachable_open` | | Open and reachable | Any open row lacks reachability |
| `mttr_days` | ✓ | Mean days to resolve | Nothing was fixed |
| `mttr_critical_days` | ✓ | Mean days to resolve criticals | No criticals were fixed |
| `median_fix_days` | ✓ | Median days to fix | Nothing was fixed |
| `p90_fix_days` | ✓ | 90th percentile days to fix | Nothing was fixed |
| `mean_open_age_days` | | Mean age of open findings | No open findings |
| `sla_compliance` | ✓ | % of fixes made within SLA | Nothing was fixed |
| `over_sla` | | Open past the SLA deadline | — |
| `due_7_days` | | Open, due within 7 days | — |
| `ignored` | | Currently ignored | — |
| `critical_ignored` | | Currently ignored criticals | — |
| `ignore_rate` | ✓ | Ignored ÷ (fixed + ignored) % | No fixes or ignores in the period |
| `jira_linkage` | | % of open critical+high linked to Jira | No open critical+high, or Jira data missing |
| `fix_rate`, `risk_score`, `product_coverage`, `projects_monitored`, `stale_projects`, `scans_run`, `pr_pass_rate`, `issues_prevented`, `issue_density`, `new_per_project` | | Placeholders | Always. These need inventory, history or an approved risk model. Build usage, PR-check and prevention numbers as custom metrics instead. |

The issue data holds only the latest lifecycle dates, so fix and reopen flows and MTTR are approximations. Pulse calculates backlog from the current snapshot and does not rebuild past backlog.

## 11. Add datasets, metrics and an SLA policy

### 11.1 SLA policy file

```json
{ "critical": 7, "high": 30, "medium": 90, "low": 180 }
```

Load it with `--sla ./sla.json`, or change it on the **SLA policy** page. Changes apply to all views and reports.

### 11.2 Custom metrics

**In the dashboard:** open **Data & metrics → Add your own metrics**. The page has a step-by-step guide, six examples you can insert with one click, a field and operator reference, and **Your columns**: every column in your loaded data with sample values (click a name to copy it). Edit the JSON, click **Apply metric definitions**, and the results appear as tiles under **Your additional metrics** on every dashboard. JSON mistakes are reported next to the editor with the line number. Applied metrics are saved in `~/.snyk-pulse` and come back after a restart; apply `[]` to remove them.

Column names differ between Snyk exports: the Issues CSV calls the repository `PROJECT_TARGET`, the Export API calls it `PROJECT_TARGET_DISPLAY_NAME`. Always check **Your columns** for the name in your data; a metric that names a missing column shows the reason on its tile instead of a number.

**From the command line:**

Load a file with `--metrics ./metrics.json`, or edit, upload and apply definitions in **Data & metrics → Add your own metrics**. Click **Save definitions file** to reuse them later. Example ([examples/metrics.json](../examples/metrics.json)):

```json
[
  {
    "id": "critical_open",
    "label": "Open critical findings",
    "dataset": "issues",
    "window": "snapshot",
    "aggregate": "count",
    "where": [
      { "field": "ISSUE_STATUS", "op": "eq", "value": "Open" },
      { "field": "ISSUE_SEVERITY", "op": "eq", "value": "Critical" }
    ]
  }
]
```

| Field | Required | Values |
| --- | --- | --- |
| `id` | Yes | Unique: lowercase letters, digits and `_`, starting with a letter |
| `label` | No | Display name |
| `dataset` | Yes | A registered dataset name |
| `window` | Yes | `snapshot` (all rows) or `period` (rows whose `dateField` is in the selected period) |
| `dateField` | If `period` | Column holding the event date |
| `aggregate` | Yes | `count`, `distinct`, `sum`, `mean`, `percentage` |
| `field` | For `distinct`, `sum`, `mean` | The column to aggregate |
| `where` | No | Row filters; every rule must match |
| `numerator` | For `percentage` | Rules for the numerator. The denominator is the rows matching `where`. |
| `unit` | No | Display suffix, such as `%` |
| `scopeFields` | No | Map dashboard filters (`org_id`, `project_id`, `group`, `product`, `severity`) to this dataset's columns |

**Rule operators:**

- `eq`, `ne` and `in` (`in` takes an array). These comparisons ignore case.
- `gt`, `gte`, `lt` and `lte` compare numbers.
- `present` matches a non-empty value.

Each list can hold up to 25 rules. Definitions are data only; Pulse never runs code from them. A metric shows "Unavailable" with a reason when its dataset, columns or dates are missing.

### 11.3 Register another Export API dataset

```json
[{ "name": "my_dataset", "label": "My dataset", "dateFilter": "updated" }]
```

- `name` is the exact Snyk dataset identifier: lowercase, at most 64 characters, and not a built-in name.
- `dateFilter` is `introduced`, `updated` or `event`.

Use the file in one of these ways:

```sh
node pulse.mjs --registry ./datasets.json --org YOUR_ORG_UUID --datasets issues,my_dataset
node pulse.mjs --registry ./datasets.json --dataset my_dataset=./data.csv
```

You can also paste it into **Data & metrics → Register another dataset**. Registering a dataset only names it; it doesn't make Snyk support it. Pulls always go to the regional Snyk API, and custom URLs are not accepted.

For a new API source beyond the Export API, see the adapter contract in [EXTENSIONS.md](EXTENSIONS.md).

## 12. Build and package Pulse (maintainers)

End users skip this section. The backend uses only Node built-ins. The dashboard is a React/TypeScript and ECharts app in `frontend/`, compiled into `web/`, which is checked in so that users need no build.

### 12.1 Rebuild the dashboard

From the repository root:

```sh
npm --prefix snyk-pulse/frontend ci     # install UI build tools (first time or after dependency changes)
npm --prefix snyk-pulse run build       # type-check, build with Vite, replace web/
```

The build runs `tsc --noEmit && vite build` in `frontend/`, replaces `web/` with `frontend/dist/`, and copies `index.html` to `web/Snyk Pulse.dc.html`. Then check it:

```sh
node pulse.mjs --demo        # inspect the UI in the browser
node pulse.mjs --demo --out ./pulse-reports --no-serve
```

### 12.2 Refresh the bundled report generator

`vendor/snyk-auto-report.mjs` is a generated copy of `snyk_report/snyk-auto-report.mts`; do not edit it. After changing `snyk_report`, run from `snyk-pulse/`:

```sh
npm run vendor:report
```

This bundles the source with esbuild (from the snyk-scripts root `node_modules`), records the source commit in the file header, and checks the result runs before keeping it.

### 12.2a Package a release archive

The archive holds the runtime files under a `snyk-pulse/` folder. Rebuild it after every UI build so that it carries the current `web/`. From the repository root:

```sh
COPYFILE_DISABLE=1 tar -czf snyk-pulse/snyk-pulse-utility.tgz \
  snyk-pulse/pulse.mjs snyk-pulse/package.json snyk-pulse/README.md \
  snyk-pulse/lib snyk-pulse/web snyk-pulse/examples snyk-pulse/docs
```

`COPYFILE_DISABLE=1` stops macOS from adding `._*` metadata files. Never ship a copy without `web/`, because Pulse cannot serve the dashboard without it. `*.tgz` is ignored by git.

### 12.3 Project layout

```text
pulse.mjs             CLI entry point and option parsing
lib/connection.mjs    Regions, token validation, group/org discovery
lib/snyk.mjs          Export API client: submit, poll, download, retry, resume
lib/csv.mjs           CSV parsing, issue normalization, CSV output encoding
lib/metrics.mjs       Built-in metric engine and SLA policy validation
lib/extensions.mjs    Dataset registry and custom metric engine
lib/session.mjs       In-memory session, atomic dataset loading, version restore, demo data
lib/store.mjs         Saved versions, last source and token (built-in SQLite)
lib/server.mjs        Local HTTP server, API routes, report CSVs
lib/runtime.mjs       Fixed-port lifecycle, instance registry, --stop
lib/network.mjs       Network and TLS error messages (no secrets echoed)
web/                  Prebuilt dashboard (runtime)
frontend/             Dashboard source and build tooling (maintainers)
examples/             Sample metrics.json and registry.json
scripts/build-ui.mjs  Builds the UI and refreshes web/
docs/                 This guide, metric semantics, extensions, plan
```

## 13. Sessions, ports and stopping Pulse

- Pulse listens only on `127.0.0.1`, on port **8780** unless you set `--port` (which is remembered). A previous Pulse instance on that port is stopped automatically. If another program holds the port, Pulse names it and stops with an error rather than killing that program or choosing a random port.
- Starting Pulse again stops your previous Pulse instance first, which clears its data and tokens and cancels any active pull. Headless (`--no-serve`) runs never start or stop a dashboard.
- On macOS/Linux, a suspended Pulse process is verified using its owner, CLI path and listening PID before being resumed for authenticated shutdown. This requires `ps` and `lsof`. Use Ctrl+C to stop; Ctrl+Z only pauses the process.
- `node pulse.mjs --stop` stops your running Pulse instances, after verifying each one with a private shutdown key.
- Each start prints a new launch link. Older links stop working.
- Pulse keeps a small control record (process ID, port, instance ID and shutdown key; never tokens or data) in a private folder under the system temp directory. Pulse removes it on shutdown.

## 14. Troubleshooting

| Message or symptom | Fix |
| --- | --- |
| `Snyk Pulse requires Node 22 or newer.` | Upgrade Node. |
| `Open the launch URL printed in your terminal.` | Use the full `/launch/…` link from the latest start, not the bare port. |
| `Port 8780 is used by another application…` | Run once with a free port, e.g. `--port 8781`; Pulse remembers it. |
| `Cannot verify the previous Pulse instance…` | A suspended instance of this utility is recovered automatically when `ps` and `lsof` can verify it. If verification still fails, return to its original terminal, run `fg`, then press Ctrl+C. Unverified processes are left untouched. |
| `Snyk rejected this token…` (401) | Check the region and whether the token has expired or been revoked. |
| `Snyk denied access…` / `This token cannot export the selected scope/dataset` (403) | The token's role or Snyk plan lacks Export API access for that scope or dataset. |
| `Snyk export submission is rate limited (20 POSTs/hour)` | Wait, then retry. Reduce schedule frequency or the number of datasets. |
| Groups or organizations are missing from the list | Use **Enter a scope UUID instead**. Discovery can be more restricted than export access. |
| `TLS certificate verification failed…` | Set `NODE_EXTRA_CA_CERTS` to your company's CA bundle and restart Pulse. |
| `Snyk returned an unexpected redirect…` | Check the region, and any proxy or sign-in gateway. |
| A pull stopped partway | Click **Resume existing export** in the same session. After a restart, use **Resume an export from a previous session**, or `--export-id UUID` with the original scope, region and one dataset. |
| `The submission outcome is unknown…` | The connection dropped while submitting. Check Snyk before starting a new export; Pulse never resubmits automatically. |
| `Snyk export … failed on the server.` | Start a new export after checking the dataset and scope. |
| `Export exceeds 100,000 rows` / `50 MiB` | Report on a smaller scope, such as one organization instead of the whole group. |
| `CSV record N: …` | Fix that row ([validation rules](#92-issues-csv-columns)). The previous data stays loaded. |
| `Missing required issue columns: …` | Export the full issues dataset, including the required columns. |
| `--no-serve requires --out DIRECTORY.` | Add `--out`. |
| `--out needs an issues dataset.` | Include `issues` in the input. |
| A metric shows "Unavailable" | Hover the ⓘ icon or check the **Metric dictionary** for the missing input. |

## 15. How Pulse handles data and credentials

- Loaded data, the last data source and the validated Snyk token are saved in `~/.snyk-pulse/pulse.db` (owner-only SQLite, last 10 versions). The token is stored in plain text so Refresh works after a restart. Use `--no-store` to keep a session in memory only, or `--forget` to delete everything saved. Nothing is sent to any service except Snyk.
- Tokens go only to the regional Snyk API you chose. Export file downloads use signed links from Amazon S3 or Google Cloud Storage, without your token.
- Error messages and logs redact the token and never include signed download links.
- The dashboard needs a per-launch session cookie and blocks requests from other sites.
- Report files are written only when you ask for them, with owner-only permissions.
- Pulse is a single-user local tool. It has no accounts, server-side schedules or outbound notifications.
