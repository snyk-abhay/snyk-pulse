# Snyk Pulse

Turn a Snyk CSV export or a Snyk API token into security dashboards and shareable reports with one command. Pulse runs locally in your browser: **Node.js 22+ only — no Python, database server, Docker or `npm install` needed to run it.** The dashboard ships prebuilt in `web/`.

- [Setup](#setup) · [Run](#run) · [Use the dashboard](#use-the-dashboard) · [Generate reports](#generate-reports) · [Build (maintainers)](#build-maintainers) · [Request a feature](#request-a-feature-or-report-a-bug)

---

## Setup

### 1. Requirements

| Need | Version | Check |
| --- | --- | --- |
| Node.js | **22.13 or newer** (24 recommended) | `node --version` |
| Google Chrome, Chromium or Microsoft Edge | Any recent version | Only for **PDF** reports |

Node 22.0–22.12 still runs Pulse, but without saved data (that needs Node's built-in SQLite, 22.13+). Nothing else is installed.

### 2. Get Pulse

```sh
git clone https://github.com/snyk-abhay/snyk-pulse.git
cd snyk-pulse
```

This repository is self-contained: you can copy the folder anywhere and run it.

### 3. Get your data — one of

- **A Snyk CSV export** — Snyk UI → **Reports** → export issues, or an Export API CSV. No token needed.
- **A Snyk API token** — to pull data directly and use **Refresh**:

| Token | Where to get it | Use |
| --- | --- | --- |
| Personal access token (PAT) | **My Profile → Personal access tokens** | Local reports with your own permissions |
| Legacy personal API token | **My Profile → API key** (if available) | Your own permissions |
| Group service-account token | **Group → Settings → Service accounts** | Group-wide reporting and automation |
| Org service-account token | **Organization → Settings → Service accounts** | One organization |

Tokens are **region-specific** (`us`, `us02`, `eu`, `au`, `gov`) — a US token does not work against EU. Paste the token value only, without an `Authorization` prefix. See Snyk's [API authentication](https://docs.snyk.io/developer-tools/snyk-api/authentication-for-api) and [service accounts](https://docs.snyk.io/platform-administration/service-accounts/service-accounts) guides. Your plan must include Export API access for API pulls.

---

## Run

From the repository root:

```sh
node pulse.mjs
```

Your browser opens at `http://127.0.0.1:8780` with a one-time launch link (also printed in the terminal — always use that link). Choose **CSV file** or **Snyk API** and follow **Connect → Scope → SLA policy → Review**. **Ctrl+C** stops Pulse.

### Common commands

```sh
node pulse.mjs --csv ./issues.csv                 # start with a CSV
node pulse.mjs --demo                             # explore with synthetic data
SNYK_TOKEN=... node pulse.mjs --org ORG_UUID --region eu   # pull from the API
node pulse.mjs --port 8781                        # use another port (remembered)
node pulse.mjs --stop                             # stop a running Pulse
node pulse.mjs --help                             # every option
```

Provide `SNYK_TOKEN` through your environment or secret manager rather than typing a token literal in a command; `--api-key` also exposes it in process arguments.

### What happens between runs

- **Your data is saved.** Every CSV import or API pull is stored as a dated version (last 10 kept) in `~/.snyk-pulse/pulse.db`. The next launch reopens it — no need to upload or reconnect.
- **Same port, same session.** Pulse uses port **8780** (or the last `--port` you passed). Running it again stops the previous Pulse instance first. If another program owns the port, Pulse names it and leaves it running — pick another `--port` once.
- **Refresh** (top bar) pulls the saved API scope again up to today and saves a new version.
- `--no-store` runs memory-only; `--forget` deletes saved data and the token.

### Script / scheduler mode

```sh
node pulse.mjs --csv issues.csv --out ./reports --no-serve
SNYK_TOKEN=... node pulse.mjs --org ORG_UUID --out ./reports --no-serve
```

Writes `metrics.csv` and `open-issues.csv`, then exits — suitable for cron. See the [user guide](docs/USER_GUIDE.md#7-run-pulse-from-a-scheduler).

---

## Use the dashboard

| Section | Page | For |
| --- | --- | --- |
| Dashboards | **CISO dashboard** | Leadership: open critical/high, exploitable, SLA compliance, critical MTTR, risk trend, risk by product, organizations over SLA |
| | **Application security** | Security triage: exploitable + reachable, mature exploits, secrets, OWASP Top 10, top CWEs, most widespread CVEs |
| | **Engineering** | Developers: searchable repository leaderboard, top vulnerable packages with fix versions, project types, branches |
| | **Organization scorecard** | One organization's KPIs (select an org on the CISO dashboard) |
| Explore | **Metric explorer** / **Metric dictionary** | Any metric grouped by org/product/severity; definition of every number |
| Reports | **Generate report** | Full PDF/HTML/CSV/JSON reports ([below](#generate-reports)) |
| | **Report library** / **Report builder** | Quick CSV downloads; assemble and print a report |
| Configure | **Data & metrics** | Saved versions, Refresh, loaded datasets, **custom metrics** (guided, with examples), dataset registration |
| | **SLA policy** | Severity deadlines used everywhere |

Every dashboard has a **Remediation work list** with search, filters (severity, product, type, organization, repository) and infinite scroll. Dark and light themes are supported.

**CSV requirements:** UTF-8, up to 50 MiB / 100,000 rows, with `PROBLEM_ID`, `ORG_PUBLIC_ID`, `ISSUE_SEVERITY`, `ISSUE_STATUS`, `FIRST_INTRODUCED`. Pulse detects an issues export from its columns. Missing optional data (fixability, exploitability, reachability, KEV) is shown as unavailable, never as zero. Details: [metric semantics](docs/METRICS.md).

**Custom metrics:** open **Data & metrics → Add your own metrics** for a step-by-step guide, insertable examples and a list of your real column names. Applied metrics are saved and appear on every dashboard. Format reference: [EXTENSIONS.md](docs/EXTENSIONS.md).

---

## Generate reports

**Reports → Generate report** produces a complete, shareable vulnerability report — cover, executive summary, findings index and register, per-finding details and appendix — using Pulse's bundled copy of the [snyk_report](https://github.com/snyk-abhay/snyk-scripts/tree/main/snyk_report) generator.

1. **Data** — *Loaded data* (instant, no Snyk call) or *Live from Snyk* (fresh Export API pull with the saved token; counts toward Snyk's 20 exports/hour).
2. **Period** — last 7/14/30/90 days, 6 months, 365 days, 2 years, all history, *from a date*, or a *custom date range*.
3. **Filters** — severity, status, product, detail limits.
4. **Cover** — title, prepared for/by, classification.
5. **Formats** — PDF (needs Chrome/Edge), HTML, CSV, JSON.

Reports run in the background (cancellable) and are saved in `~/.snyk-pulse/reports/` with download links.

---

## Build (maintainers)

End users never need this — `web/` and `vendor/` are committed prebuilt.

### Prerequisites

- Node.js 22.13+ and npm.
- The checked-in report generator needs no build. To regenerate it, provide the original report source at `../snyk_report/snyk-auto-report.mts` and esbuild at `../node_modules/.bin/esbuild`, as expected by `scripts/vendor-report.mjs`. The UI build does not need those external files.

### Rebuild the dashboard UI

The UI source is React + TypeScript + ECharts in `frontend/`.

```sh
npm --prefix frontend ci        # first time only
npm run build                   # type-checks, builds, and copies the result into web/
```

Commit `web/` together with your `frontend/src` changes — Pulse serves `web/`, not the source.

For a quicker loop while editing, rebuild and restart: `npm run build && node pulse.mjs`.

### Refresh the bundled report generator

`vendor/snyk-auto-report.mjs` is a generated single-file copy of `../snyk_report/snyk-auto-report.mts`. After changing `snyk_report`:

```sh
npm run vendor:report           # bundles with esbuild, stamps the source commit, verifies it runs
```

Do not edit `vendor/` by hand.

### Project layout

```text
pulse.mjs                CLI entry point
lib/                     Backend (Node built-ins only): CSV, metrics, Snyk API, server,
                         saved data (store.mjs), report generation (reports.mjs), OWASP mapping
web/                     Prebuilt dashboard served at runtime (generated — do not edit)
vendor/                  Bundled report generator (generated — do not edit)
frontend/                UI source: React/TypeScript (maintainers only)
scripts/build-ui.mjs     Builds frontend/ into web/
scripts/vendor-report.mjs  Copies snyk_report into vendor/
docs/                    User guide, metric semantics, extension guide, development plan
```

### Quick check

```sh
node pulse.mjs --demo --out ./pulse-reports --no-serve
```

Loads synthetic data, writes the standard CSV reports and exits.

---

## Security and local data

- Pulse listens on `127.0.0.1` only, with a random per-session launch link and cookie. It is a single-user local tool.
- Snyk tokens go only to the selected regional Snyk API. **A validated token is saved in plain text** in `~/.snyk-pulse/pulse.db` (folder `0700`, file `0600`) so Refresh works after a restart — use `--no-store` or `--forget` if that is not acceptable.
- No telemetry and no remote UI assets. The report generator receives the token via its environment only, never on the command line.

---

## Request a feature or report a bug

Have an idea for a new dashboard, metric, report option or data source — or found something broken? **Open an issue on GitHub:**

**→ [github.com/snyk-abhay/snyk-scripts/issues](https://github.com/snyk-abhay/snyk-pulse/issues/new/choose)**

Choose **Feature request** or **Bug report** and start the title with `[Snyk Pulse]`. Helpful details:

- **Feature:** who it is for (CISO, AppSec, engineering), the problem it solves, and an example of the number, chart or report you want.
- **Bug:** steps to reproduce, what you expected, what happened, your Node version (`node --version`), OS, and whether you used CSV or the API. **Never paste tokens, signed URLs or customer data.**

Check [existing issues](https://github.com/snyk-abhay/snyk-pulse/issues?q=is%3Aissue+%22Snyk+Pulse%22) first and add a 👍 to ones you want.

---

More detail: [User guide](docs/USER_GUIDE.md) · [Metric semantics](docs/METRICS.md) · [Custom metrics & datasets](docs/EXTENSIONS.md) · [Development plan](docs/DEVELOPMENT_PLAN.md)
