# Snyk Pulse — utility development plan

Updated 9 October 2026. This supersedes the earlier full-application plan following the request for a one-command JavaScript utility.

## Delivery

1. **Single-command runtime — implemented.** Node 22+, no runtime packages, Python, database or container. Fixed port 8780 by default (last explicit `--port` remembered), authenticated replacement of registered older Pulse instances, and `--stop`; no random-port fallback or termination of unrelated services. Open a session with CSV, API options, or browser setup. Bundle the UI in the release folder.
2. **CSV and API ingestion — implemented.** Strict atomic CSV import; token identity validation before export; paginated group/organization discovery and group filtering; personal and service-account token guidance; regional Snyk Export API client; selected datasets; poll/download/cancel, GET retries and export-ID resume. Keep tokens only in process memory. Scope discovery can be restricted independently of export access, with an explicit UUID fallback.
3. **Shared calculations — implemented.** Use one metric engine for persona views, explorer and CSVs. Separate snapshot backlog from activity-period metrics. Show unavailable inputs explicitly.
4. **Extensibility — implemented.** Add dataset registry entries and declarative metric definitions from the command line or Data & metrics. Provide a documented JavaScript adapter contract for future API routes.
5. **Claude Design implementation — implemented for the utility scope.** Import Snyk Pulse.dc.html and its referenced design-system/support files through the authenticated MCP. Use its dark/light palette, local Geist font, wordmark, halftone asset, setup progression, navigation, dashboard structure, metric explorer/dictionary and report flow. Replace sign-in with CSV/API setup. Eliminate account management and fake sync/history values.
6. **Reports — implemented.** Scope-consistent metric/open-finding/breach CSV, configurable report sections, browser print/PDF, headless report output for an OS scheduler.
7. **Verification.** The initial build passed regression/browser checks and security review. Automated test files and runners were subsequently removed at the user’s request. The remaining checks are the production UI build and a direct CLI launch/report smoke check. Live Snyk account validation remains outstanding.

## Follow-up work that requires additional evidence

- Run against an explicitly supplied real Snyk token, Group and representative exports. Reconcile counts with identical Snyk Reports scope. Mock tests do not establish live endpoint entitlement or metric parity.
- Add inventory schemas and validated custom definitions for usage, PR and prevention metrics from real customer exports.
- Saved versions (last 10) and Refresh are implemented in `lib/store.mjs` using built-in SQLite. A possible next step is comparing two versions side by side.
- Historical backlog, complete reopen cycles, approved risk weights and inventory denominators require additional data. Do not manufacture these from a current snapshot.
- Native PPTX, scheduled delivery and account/tenant features are outside this utility increment. Browser print/PDF and OS scheduling cover the current local workflow.

## Acceptance

A user with Node runs one command, brings CSV or API scope, sees actual metrics, changes persona/filter/SLA, adds a custom metric and exports reports. No npm installation or build is needed to use the checked-in release. Token and data lifecycle are clear, and unsupported metrics remain unavailable.
