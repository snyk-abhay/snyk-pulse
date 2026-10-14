import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import type { AppState, Policy, SnykConnection, SnykScope } from "./types";
import { mutate, request, titleCase, today } from "./api";
export function Brand() {
  return (
    <div className="brand">
      <img src="/brand/snyk-wordmark.png" alt="snyk" />
      <span>Pulse</span>
    </div>
  );
}
export function ThemeToggle({
  theme,
  onToggle,
}: {
  theme: "dark" | "light";
  onToggle: () => void;
}) {
  const next = theme === "dark" ? "Light" : "Dark";
  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={onToggle}
      aria-label={`Switch to ${next.toLowerCase()} theme`}
      title={`Switch to ${next.toLowerCase()} theme`}
    >
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
        {theme === "dark" ? (
          <>
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5" />
          </>
        ) : (
          <path d="M20.8 13A9 9 0 0 1 11 3.2 9 9 0 1 0 20.8 13Z" />
        )}
      </svg>
      <span>
        {next}
        <span className="theme-label-suffix"> theme</span>
      </span>
    </button>
  );
}
export function PolicyFields({
  policy,
  setPolicy,
}: {
  policy: Policy;
  setPolicy: (p: Policy) => void;
}) {
  return (
    <div className="policy-fields">
      {Object.entries(policy).map(([key, v]) => (
        <label key={key}>
          <span className={"severity " + key}>{titleCase(key)}</span>
          <span>
            <input
              aria-label={`${titleCase(key)} SLA days`}
              required
              type="number"
              min="1"
              max="3650"
              value={Number.isNaN(v) ? "" : v}
              onChange={(e) =>
                setPolicy({ ...policy, [key]: e.target.valueAsNumber })
              }
            />{" "}
            days
          </span>
        </label>
      ))}
    </div>
  );
}
function StepMark({ number, complete }: { number: number; complete: boolean }) {
  return (
    <span
      className={"step-mark" + (complete ? " complete" : "")}
      aria-hidden="true"
    >
      {complete ? (
        <svg key="check" viewBox="0 0 24 24" fill="none">
          <path d="m6 12 4 4 8-9" />
        </svg>
      ) : (
        number
      )}
    </span>
  );
}
// Required issue columns (lib/csv.mjs normalizeIssues); their presence identifies an issues export.
const ISSUE_COLUMNS = [
  "PROBLEM_ID",
  "ORG_PUBLIC_ID",
  "ISSUE_SEVERITY",
  "ISSUE_STATUS",
  "FIRST_INTRODUCED",
];

export function Setup({
  state,
  refresh,
  onDone,
  onCancel,
  theme,
  onToggleTheme,
}: {
  state: AppState;
  refresh: () => void;
  onDone: () => void;
  onCancel?: () => void;
  theme: "dark" | "light";
  onToggleTheme: () => void;
}) {
  const recovering = state.job?.running || state.job?.stage === "error";
  const [source, setSource] = useState<"csv" | "api">(
      recovering ? "api" : "csv",
    ),
    [step, setStep] = useState(
      state.job?.running || state.job?.stage === "error" ? 4 : 1,
    ),
    [completedThrough, setCompletedThrough] = useState(recovering ? 3 : 0),
    [submitted, setSubmitted] = useState(!!recovering),
    [imported, setImported] = useState(false),
    [errorStep, setErrorStep] = useState(1),
    [region, setRegion] = useState(
      (state.connectionRegion || "us")
        .toLowerCase()
        .replaceAll("-", "")
        .replace(/^us01$/, "us"),
    ),
    [token, setToken] = useState(""),
    [storedToken, setStoredToken] = useState(state.hasToken),
    [connection, setConnection] = useState<SnykConnection | null>(null),
    [manualScope, setManualScope] = useState(false),
    [groupFilter, setGroupFilter] = useState(""),
    [groupOrgs, setGroupOrgs] = useState<SnykScope[]>([]),
    [groupWarnings, setGroupWarnings] = useState<string[]>([]),
    [scope, setScope] = useState("org"),
    [id, setId] = useState(""),
    [selected, setSelected] = useState(["issues"]),
    [resumeKnownExport, setResumeKnownExport] = useState(false),
    [exportId, setExportId] = useState(state.job?.exportId || ""),
    [dataset, setDataset] = useState("issues"),
    [date, setDate] = useState(today()),
    [file, setFile] = useState<File | null>(null),
    [detected, setDetected] = useState<"issues" | "other" | null>(null),
    [policy, setPolicy] = useState(state.policy),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const sections = useRef<(HTMLElement | null)[]>([]);
  const [moreBelow, setMoreBelow] = useState(false);
  const priorJob = useRef<AppState["job"]>(null);
  const job =
    submitted && source === "api" && state.job !== priorJob.current
      ? state.job
      : null;
  const finished =
    submitted && (source === "csv" ? imported : job?.stage === "complete");
  const locked = busy || !!state.job?.running;
  const goToStep = (next: number) => {
    setStep(next);
    requestAnimationFrame(() => {
      const section = sections.current[next - 1];
      section
        ?.querySelector<HTMLHeadingElement>("h2")
        ?.focus({ preventScroll: true });
      const content = section?.querySelector(".onboarding-content");
      if (content) content.scrollTop = 0;
    });
  };
  useEffect(() => {
    if (recovering) goToStep(4);
  }, []);
  useEffect(() => {
    const content = sections.current[step - 1]?.querySelector<HTMLElement>(
      ".onboarding-content",
    );
    if (!content) return;
    const measure = () =>
      setMoreBelow(
        content.scrollHeight - content.clientHeight - content.scrollTop > 8,
      );
    const observer = new ResizeObserver(measure);
    observer.observe(content);
    if (content.firstElementChild) observer.observe(content.firstElementChild);
    content.addEventListener("scroll", measure, { passive: true });
    // Expanded token guidance also changes the available content height.
    content.addEventListener("toggle", measure, true);
    measure();
    return () => {
      observer.disconnect();
      content.removeEventListener("scroll", measure);
      content.removeEventListener("toggle", measure, true);
    };
  }, [step]);
  const invalidateFrom = (number: number) => {
    setCompletedThrough((previous) => Math.min(previous, number - 1));
    setSubmitted(false);
    setImported(false);
    setError("");
  };
  const advance = (number: number) => {
    setError("");
    setCompletedThrough((previous) => Math.max(previous, number));
    goToStep(number + 1);
  };
  const connectSource = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setErrorStep(1);
    if (source === "api" && !connection) {
      void validateToken(event);
      return;
    }
    if (source === "csv" && (!file || file.size > 50 * 1024 * 1024)) {
      setError(file ? "CSV exceeds 50 MiB." : "Choose a CSV file.");
      return;
    }
    advance(1);
  };
  const approveScope = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setErrorStep(2);
    if (source === "api" && (!connection || !id || !selected.length)) {
      setError("Validate your token and select a scope and dataset.");
      return;
    }
    advance(2);
  };
  const scopes =
    scope === "group"
      ? connection?.groups || []
      : groupFilter
        ? groupOrgs
        : connection?.orgs || [];
  const invalidate = () => {
    invalidateFrom(1);
    setConnection(null);
    setId("");
    setGroupFilter("");
    setGroupWarnings([]);
    setError("");
  };
  const validateToken = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    invalidate();
    try {
      const result = await request<SnykConnection>("/api/connection/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Pulse-Local": "1" },
        body: JSON.stringify({ token, region }),
      });
      setConnection(result);
      setToken("");
      setStoredToken(true);
      setRegion(result.region);
      const useGroup = !result.orgs.length && !!result.groups.length;
      const choices = useGroup ? result.groups : result.orgs;
      setScope(useGroup ? "group" : "org");
      setId(choices[0]?.id || "");
      setManualScope(!choices.length);
      advance(1);
      refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const filterGroup = async (group: string) => {
    setErrorStep(2);
    setGroupFilter(group);
    setGroupWarnings([]);
    setId("");
    setGroupOrgs([]);
    if (!group) {
      setId(connection?.orgs[0]?.id || "");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const result = await request<{ orgs: SnykScope[]; warnings: string[] }>(
        "/api/connection/orgs",
        {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Pulse-Local": "1" },
          body: JSON.stringify({ connectionId: connection?.id, group }),
        },
      );
      setGroupOrgs(result.orgs);
      setGroupWarnings(result.warnings);
      setId(result.orgs[0]?.id || "");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const load = async (e: FormEvent) => {
    e.preventDefault();
    setErrorStep(4);
    if (locked || completedThrough < 3 || submitted) return;
    priorJob.current = state.job;
    setBusy(true);
    setError("");
    try {
      await mutate("/api/policy", policy, "PUT");
      if (source === "csv") {
        if (!file) throw new Error("Choose a CSV file.");
        if (file.size > 50 * 1024 * 1024)
          throw new Error("CSV exceeds 50 MiB.");
        await request(
          "/api/import?" +
            new URLSearchParams({ dataset, as_of: date, file_name: file.name }),
          {
            method: "POST",
            headers: { "Content-Type": "text/csv", "X-Pulse-Local": "1" },
            body: file,
          },
        );
        setImported(true);
        setSubmitted(true);
        goToStep(4);
        refresh();
      } else {
        if (!connection)
          throw new Error("Validate your token before pulling data.");
        await mutate("/api/connect", {
          connectionId: connection.id,
          [scope]: id,
          datasets: selected,
          ...(resumeKnownExport ? { exportId: exportId.trim() } : {}),
        });
        setToken("");
        setSubmitted(true);
        goToStep(4);
        refresh();
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const demo = async () => {
    setErrorStep(1);
    setBusy(true);
    try {
      await mutate("/api/demo");
      refresh();
      onDone();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const resume = async () => {
    setErrorStep(4);
    setBusy(true);
    setError("");
    try {
      await mutate("/api/resume");
      refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const labels = ["Connect", "Scope", "SLA policy", "Review"];
  const scopeName = scopes.find((entry) => entry.id === id)?.name || id;
  const section = (
    number: number,
    title: string,
    description: string,
    contents: ReactNode,
    onSubmit: (event: FormEvent<HTMLFormElement>) => void,
    action?: string,
  ) => {
    const enabled = completedThrough >= number - 1;
    const done = number === 4 ? finished : completedThrough >= number;
    return (
      <section
        ref={(element) => {
          sections.current[number - 1] = element;
        }}
        id={"setup-step-" + number}
        className={
          "panel setup-card onboarding-section" +
          (done ? " complete" : "") +
          (step === number ? " active" : "")
        }
        aria-labelledby={"setup-title-" + number}
        aria-hidden={step !== number}
        inert={step !== number}
      >
        <header className="onboarding-heading">
          <StepMark number={number} complete={!!done} />
          <div>
            <span className="onboarding-kicker">STEP {number} OF 4</span>
            <h2 id={"setup-title-" + number} tabIndex={-1}>
              {title}
            </h2>
            {description && <p>{description}</p>}
          </div>
          <span className={"step-status" + (done ? " complete" : "")}>
            {done
              ? "Completed"
              : enabled
                ? number === 4 && job?.running
                  ? "In progress"
                  : "Ready"
                : "Up next"}
          </span>
        </header>
        <form
          className="onboarding-form"
          onSubmit={onSubmit}
          aria-busy={busy}
          onChangeCapture={
            number === 2 || number === 3
              ? () => invalidateFrom(number)
              : undefined
          }
        >
          <fieldset
            disabled={
              !enabled || step !== number || (number === 4 ? busy : locked)
            }
          >
            <div className="onboarding-content">
              <div className="onboarding-fields">
                {error && errorStep === number && (
                  <div className="alert error" role="alert">
                    {error}
                  </div>
                )}
                {contents}
              </div>
            </div>
            <button
              type="button"
              className="scroll-cue"
              data-visible={step === number && moreBelow}
              aria-hidden={step !== number || !moreBelow}
              tabIndex={step === number && moreBelow ? 0 : -1}
              onClick={() => {
                const content = sections.current[
                  number - 1
                ]?.querySelector<HTMLElement>(".onboarding-content");
                content?.scrollBy({
                  top: content.clientHeight * 0.7,
                  behavior: window.matchMedia(
                    "(prefers-reduced-motion: reduce)",
                  ).matches
                    ? "auto"
                    : "smooth",
                });
              }}
            >
              <span>Scroll for more</span>
              <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path d="M12 4v15m-6-6 6 6 6-6" />
              </svg>
            </button>
            {(action || (number === 4 && !submitted)) && (
              <div className="form-actions">
                {number > 1 ? (
                  <button
                    type="button"
                    onClick={() => goToStep(number - 1)}
                    disabled={locked}
                  >
                    ← Back
                  </button>
                ) : (
                  <small>{state.store?.enabled ? "Saved locally" : "Session only"}</small>
                )}
                <button
                  className="primary"
                  disabled={
                    number === 2 &&
                    source === "api" &&
                    (!selected.length || !id || !connection)
                  }
                >
                  {busy && step === number
                    ? "Working…"
                    : action ||
                      (source === "csv"
                        ? "Import data →"
                        : resumeKnownExport
                          ? "Resume existing export →"
                          : "Pull selected datasets →")}
                </button>
              </div>
            )}
          </fieldset>
        </form>
      </section>
    );
  };
  return (
    <div className="setup">
      <header>
        <Brand />
        <div className="setup-header-actions">
          <span className="session-status">
            Local utility · {state.store?.enabled ? "saved locally" : "session only"}
          </span>
          <ThemeToggle theme={theme} onToggle={onToggleTheme} />
          {onCancel && (
            <button disabled={busy} onClick={onCancel}>
              Back to workspace
            </button>
          )}
        </div>
      </header>
      <div className="setup-layout">
        <section className="setup-work" aria-label="Report setup">
          <nav className="onboarding-nav" aria-label="Setup progress">
            <div className="onboarding-nav-title">
              <strong>Set up your report</strong>
              <span aria-live="polite">
                {finished ? 4 : completedThrough} of 4 completed
              </span>
            </div>
            <ol
              className="steps"
              style={
                {
                  "--step-progress": (finished ? 3 : completedThrough) / 3,
                } as React.CSSProperties
              }
            >
              {labels.map((label, index) => {
                const done = index === 3 ? finished : completedThrough > index;
                return (
                  <li
                    key={label}
                    className={
                      (done ? "done " : "") +
                      (step === index + 1 ? "current" : "")
                    }
                  >
                    <button
                      type="button"
                      disabled={locked || completedThrough < index}
                      aria-current={step === index + 1 ? "step" : undefined}
                      aria-label={
                        "Step " +
                        (index + 1) +
                        ": " +
                        label +
                        (done ? ", completed" : "")
                      }
                      onClick={() => goToStep(index + 1)}
                    >
                      <StepMark number={index + 1} complete={!!done} />
                      <span>{label}</span>
                    </button>
                  </li>
                );
              })}
            </ol>
          </nav>
          <div
            className={
              "setup-sections" +
              (step === 4 && submitted ? " compact-review" : "")
            }
          >
            <div
              className="setup-track"
              style={{ transform: `translateX(-${(step - 1) * 100}%)` }}
            >
              {section(
                1,
                "Connect your data",
                "",
                <>
                  <div className="source-options">
                    <button
                      type="button"
                      disabled={busy}
                      className={source === "csv" ? "selected" : ""}
                      onClick={() => {
                        setSource("csv");
                        invalidateFrom(1);
                      }}
                    >
                      <b>↑ CSV file</b>
                      <small>Import an existing export</small>
                    </button>
                    <button
                      type="button"
                      disabled={busy}
                      className={source === "api" ? "selected" : ""}
                      onClick={() => {
                        setSource("api");
                        invalidateFrom(1);
                      }}
                    >
                      <b>↗ Snyk API</b>
                      <small>Pull data from your region</small>
                    </button>
                  </div>
                  {source === "csv" ? (
                    <>
                      <label>
                        CSV file
                        <input
                          required={!file}
                          type="file"
                          accept=".csv,text/csv"
                          onChange={async (e) => {
                            const picked = e.target.files?.[0] || null;
                            setFile(picked);
                            setDetected(null);
                            invalidateFrom(1);
                            if (!picked) return;
                            // Read only the header row to identify the dataset.
                            const head = (await picked.slice(0, 64 * 1024).text())
                              .replace(/^\uFEFF/, "")
                              .split(/\r?\n/, 1)[0]
                              .split(",")
                              .map((c) => c.trim().replace(/^"|"$/g, "").toUpperCase());
                            const isIssues = ISSUE_COLUMNS.every((c) =>
                              head.includes(c),
                            );
                            setDetected(isIssues ? "issues" : "other");
                            setDataset(
                              isIssues
                                ? "issues"
                                : (state.registry.find((d) => d.name !== "issues")
                                    ?.name ?? "issues"),
                            );
                          }}
                        />
                      </label>
                      <small>
                        {file ? `Selected: ${file.name} · ` : ""}UTF-8 · maximum
                        50 MiB / 100,000 rows
                      </small>
                    </>
                  ) : (
                    <>
                      <label>
                        Snyk region
                        <select
                          aria-label="Snyk region"
                          disabled={busy}
                          value={region}
                          onChange={(e) => {
                            setRegion(e.target.value);
                            invalidate();
                          }}
                        >
                          {[
                            ["us", "US-01 · api.snyk.io"],
                            ["us02", "US-02 · api.us.snyk.io"],
                            ["eu", "EU · api.eu.snyk.io"],
                            ["au", "AU · api.au.snyk.io"],
                            ["gov", "US government"],
                          ].map(([v, l]) => (
                            <option key={v} value={v}>
                              {l}
                            </option>
                          ))}
                        </select>
                      </label>
                      <details className="token-guide">
                        <summary>
                          <span>
                            <strong>Which Snyk token should I use?</strong>
                            <small>
                              Recommended: My Profile personal access token
                              (PAT).
                            </small>
                          </span>
                          <span
                            className="token-guide-chevron"
                            aria-hidden="true"
                          >
                            ⌄
                          </span>
                        </summary>
                        <div className="token-guide-content">
                          <dl>
                            <div>
                              <dt>
                                My Profile · personal access token (PAT){" "}
                                <span className="token-recommendation">
                                  Recommended for local use
                                </span>
                              </dt>
                              <dd>
                                For your own local reports. In Snyk, open{" "}
                                <b>
                                  My Profile / Account settings → Personal
                                  access tokens
                                </b>
                                , generate a token and copy it. If your account
                                shows a legacy <b>API key</b>, use{" "}
                                <b>Click to show</b> and copy that instead.
                                Access follows your user’s permissions.
                              </dd>
                            </div>
                            <div>
                              <dt>
                                Group-level service account{" "}
                                <span className="token-recommendation">
                                  Recommended for group automation
                                </span>
                              </dt>
                              <dd>
                                For group reporting and automation. A Group
                                admin creates it in{" "}
                                <b>Group → Settings → Service accounts</b>. Its
                                role controls access to the group and
                                organizations within it.
                              </dd>
                            </div>
                            <div>
                              <dt>Organization-level service account</dt>
                              <dd>
                                For one organization. An authorized admin
                                creates it in{" "}
                                <b>
                                  Organization → Settings → Service accounts
                                </b>
                                . It does not grant access to other
                                organizations or a whole group.
                              </dd>
                            </div>
                          </dl>
                          <small>
                            A PAT belongs to a person; a service-account token
                            belongs to its group or organization. Use a service
                            account for scheduled runs. API and export access
                            require the appropriate Snyk plan and permissions.
                          </small>
                          <a
                            href="https://docs.snyk.io/developer-tools/snyk-api/authentication-for-api"
                            target="_blank"
                            rel="noreferrer"
                          >
                            Snyk token guidance ↗
                          </a>
                        </div>
                      </details>
                      <label>
                        Snyk token
                        <input
                          type="password"
                          autoComplete="off"
                          aria-describedby="token-privacy"
                          disabled={busy}
                          required={!storedToken}
                          value={token}
                          onChange={(e) => {
                            setToken(e.target.value);
                            invalidate();
                          }}
                          placeholder={
                            storedToken
                              ? "Use session token, or paste a replacement"
                              : "Paste your personal or service-account token"
                          }
                        />
                      </label>
                      <small id="token-privacy">
                        Stored in memory for this session. Validate to load your
                        groups and organizations.
                      </small>
                    </>
                  )}
                  {!state.datasets.length && (
                    <button
                      type="button"
                      className="text-button"
                      disabled={busy}
                      onClick={demo}
                    >
                      Explore with demo data →
                    </button>
                  )}
                </>,
                connectSource,
                source === "api" && !connection
                  ? "Validate token & next →"
                  : "Next: scope →",
              )}
              {section(
                2,
                "Choose scope",
                "",
                <>
                  {source === "api" ? (
                    <>
                      {connection && (
                        <div className="connection-success" role="status">
                          <strong>
                            ✓ Token validated · {connection.identity.name}
                          </strong>
                          <span>
                            {connection?.identity.type === "service_account"
                              ? "Service account"
                              : connection?.identity.type === "app_instance"
                                ? "Snyk app"
                                : "Personal account"}{" "}
                            · {region.toUpperCase()}
                          </span>
                          <small>
                            {connection?.groups.length || 0} groups listed ·{" "}
                            {connection?.orgs.length || 0} organizations listed
                          </small>
                        </div>
                      )}
                      {[...(connection?.warnings || []), ...groupWarnings].map(
                        (warning, i) => (
                          <div className="info" key={i}>
                            {warning}
                          </div>
                        ),
                      )}
                      <div className="two-fields">
                        <label>
                          Scope
                          <select
                            aria-label="Scope"
                            disabled={busy}
                            value={scope}
                            onChange={(e) => {
                              const next = e.target.value;
                              const entries =
                                next === "group"
                                  ? connection?.groups || []
                                  : connection?.orgs || [];
                              setScope(next);
                              setId(entries[0]?.id || "");
                              setManualScope(!entries.length);
                              setGroupFilter("");
                              setGroupWarnings([]);
                            }}
                          >
                            <option value="org">Organization</option>
                            <option value="group">Group</option>
                          </select>
                        </label>
                        {scope === "org" &&
                          !manualScope &&
                          !!connection?.groups.length && (
                            <label>
                              Filter by group
                              <select
                                disabled={busy}
                                value={groupFilter}
                                onChange={(e) =>
                                  void filterGroup(e.target.value)
                                }
                              >
                                <option value="">
                                  All listed organizations
                                </option>
                                {connection.groups.map((g) => (
                                  <option key={g.id} value={g.id}>
                                    {g.name}
                                  </option>
                                ))}
                              </select>
                            </label>
                          )}
                      </div>
                      {manualScope ? (
                        <label>
                          {scope === "org" ? "Organization" : "Group"} UUID
                          <input
                            required
                            value={id}
                            onChange={(e) => setId(e.target.value)}
                            pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
                            placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                          />
                        </label>
                      ) : (
                        <label>
                          {scope === "org" ? "Organization" : "Group"}
                          <select
                            required
                            disabled={busy}
                            value={id}
                            onChange={(e) => setId(e.target.value)}
                          >
                            <option value="">
                              {busy
                                ? "Loading organizations…"
                                : scopes.length
                                  ? "Choose a scope"
                                  : "No scopes listed — enter a UUID below"}
                            </option>
                            {scopes.map((s) => (
                              <option key={s.id} value={s.id}>
                                {s.name} · {s.id}
                              </option>
                            ))}
                          </select>
                        </label>
                      )}
                      <label className="manual-scope">
                        <input
                          type="checkbox"
                          checked={manualScope}
                          disabled={busy}
                          onChange={(e) => {
                            setManualScope(e.target.checked);
                            setId(e.target.checked ? "" : scopes[0]?.id || "");
                          }}
                        />
                        Enter a scope UUID instead
                      </label>
                      {manualScope && (
                        <small>
                          Use this if your token can export a known scope but
                          cannot list it. Snyk checks that scope’s export
                          permissions when the pull starts.
                        </small>
                      )}
                      <details className="token-guide">
                        <summary>
                          Resume an export from a previous session
                        </summary>
                        <div className="token-guide-content">
                          <label className="manual-scope">
                            <input
                              type="checkbox"
                              checked={resumeKnownExport}
                              onChange={(e) => {
                                setResumeKnownExport(e.target.checked);
                                if (e.target.checked)
                                  setSelected([selected[0] || "issues"]);
                              }}
                            />
                            Use an existing export ID
                          </label>
                          {resumeKnownExport && (
                            <label>
                              Export ID
                              <input
                                required
                                value={exportId}
                                onChange={(e) => setExportId(e.target.value)}
                                pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
                                placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                              />
                            </label>
                          )}
                          <small>
                            Use the original scope, region and one dataset to
                            resume the job.
                          </small>
                        </div>
                      </details>
                      <small>
                        Choose datasets. Export access depends on scope,
                        permissions and plan.
                      </small>
                      <div className="dataset-checks">
                        {state.registry.map((d) => (
                          <label key={d.name}>
                            <input
                              type={resumeKnownExport ? "radio" : "checkbox"}
                              name={
                                resumeKnownExport ? "resume-dataset" : undefined
                              }
                              checked={selected.includes(d.name)}
                              onChange={(e) =>
                                setSelected(
                                  resumeKnownExport
                                    ? [d.name]
                                    : e.target.checked
                                      ? [...selected, d.name]
                                      : selected.filter((n) => n !== d.name),
                                )
                              }
                            />
                            <span>
                              {d.label}
                              <small>{d.name}</small>
                            </span>
                          </label>
                        ))}
                      </div>
                    </>
                  ) : (
                    <>
                      {detected === "issues" ? (
                        <div className="detected-dataset">
                          <b>Dataset: Issues</b>
                          <small>
                            Detected from the columns in {file?.name}. Other
                            datasets (usage, PR checks, prevention events) are
                            separate Snyk exports; add each one as its own CSV
                            or pull it with the Snyk API.
                          </small>
                        </div>
                      ) : (
                        <label>
                          Which dataset is this file?
                          <select
                            aria-label="Dataset"
                            value={dataset}
                            onChange={(e) => setDataset(e.target.value)}
                          >
                            {state.registry
                              .filter(
                                (d) => detected !== "other" || d.name !== "issues",
                              )
                              .map((d) => (
                                <option value={d.name} key={d.name}>
                                  {d.label}
                                </option>
                              ))}
                          </select>
                          <small>
                            {detected === "other"
                              ? `${file?.name} is missing issue columns (${ISSUE_COLUMNS.join(", ")}), so it can't be loaded as Issues. Choose the export it came from.`
                              : "Each CSV holds one Snyk dataset. Choose the export this file came from."}
                          </small>
                        </label>
                      )}
                      <label>
                        Snapshot date (UTC)
                        <input
                          type="date"
                          required
                          min="1970-01-01"
                          max={today()}
                          value={date}
                          onChange={(e) => setDate(e.target.value)}
                        />
                      </label>
                      <p>
                        Use a complete export for the scope you want to report
                        on. Importing issues replaces the active snapshot
                        and saves it as a new version.
                      </p>
                    </>
                  )}
                </>,
                approveScope,
                "Next: SLA policy →",
              )}
              {section(
                3,
                "Define SLA policy",
                "Remediation deadlines in days.",
                <>
                  <PolicyFields policy={policy} setPolicy={setPolicy} />
                  <small>UTC calendar days from first introduction.</small>
                </>,
                (event) => {
                  event.preventDefault();
                  advance(3);
                },
                "Next: review →",
              )}
              {section(
                4,
                submitted
                  ? finished
                    ? "Data ready"
                    : job?.stage === "error"
                      ? "Loading interrupted"
                      : "Loading your data"
                  : "Review & load",
                finished
                  ? "Your data is ready to explore."
                  : submitted
                    ? ""
                    : "Confirm your choices before loading data.",
                <>
                  {!submitted ? (
                    <>
                      <dl className="setup-review">
                        <div>
                          <dt>Source</dt>
                          <dd>
                            {source === "csv"
                              ? file?.name || "Choose a file"
                              : "Snyk API · " + region.toUpperCase()}
                          </dd>
                        </div>
                        <div>
                          <dt>
                            {source === "csv"
                              ? "Dataset"
                              : scope === "group"
                                ? "Group"
                                : "Organization"}
                          </dt>
                          <dd>
                            {source === "csv"
                              ? dataset
                              : scopeName || "Choose a scope"}
                          </dd>
                        </div>
                        {source === "api" && (
                          <div>
                            <dt>Datasets</dt>
                            <dd>{selected.join(", ")}</dd>
                          </div>
                        )}
                        {resumeKnownExport && source === "api" && (
                          <div>
                            <dt>Existing export</dt>
                            <dd>{exportId}</dd>
                          </div>
                        )}
                        <div>
                          <dt>SLA days</dt>
                          <dd>
                            {Object.entries(policy)
                              .map(([severity, days]) => titleCase(severity) + ": " + days)
                              .join(" · ")}
                          </dd>
                        </div>
                      </dl>
                      <small>Everything stays in this local session.</small>
                    </>
                  ) : (
                    <>
                      {job && (
                        <div
                          className={
                            "alert load-status " +
                            (job.stage === "error" ? "error" : "")
                          }
                          role="status"
                        >
                          {job.message}
                          {job.exportId && <small>Export {job.exportId}</small>}
                        </div>
                      )}
                      {source === "api" && !job && (
                        <p role="status">Starting your export…</p>
                      )}
                      {job?.running || (source === "api" && !job) ? (
                        <>
                          <div className="progress">
                            <span />
                          </div>
                          <button
                            type="button"
                            className="cancel-pull"
                            onClick={async () => {
                              await mutate("/api/cancel");
                              refresh();
                            }}
                          >
                            Cancel pull
                          </button>
                        </>
                      ) : (
                        <>
                          {state.datasets.map((d) => (
                            <div className="dataset-summary" key={d.name}>
                              <b>{d.name}</b>
                              <span>
                                {d.rows.toLocaleString()} rows ·{" "}
                                {d.headers.length} columns
                              </span>
                            </div>
                          ))}
                          {state.snapshot && (
                            <p>
                              {state.options.org_id?.length || 0} organizations
                              loaded. {state.snapshot.excluded_deleted} deleted
                              rows excluded; {state.snapshot.duplicates} exact
                              duplicates removed.
                            </p>
                          )}
                          {job?.stage === "error" && (
                            <>
                              {job.canResume && (
                                <>
                                  <p>
                                    Resume keeps completed datasets and reuses
                                    accepted export jobs.
                                  </p>
                                  <button
                                    type="button"
                                    className="primary"
                                    disabled={busy}
                                    onClick={resume}
                                  >
                                    {busy
                                      ? "Resuming…"
                                      : "Resume existing export"}
                                  </button>
                                </>
                              )}
                              <button
                                type="button"
                                disabled={busy}
                                onClick={() => {
                                  invalidate();
                                  goToStep(1);
                                }}
                              >
                                Check connection
                              </button>
                            </>
                          )}
                          <button
                            type="button"
                            className="primary"
                            disabled={!state.datasets.length}
                            onClick={onDone}
                          >
                            Go to dashboard →
                          </button>
                        </>
                      )}
                    </>
                  )}
                </>,
                load,
              )}
            </div>
          </div>
        </section>
        <section className="setup-story">
          <div className="eyebrow">SECURITY KPIs FOR SNYK CUSTOMERS</div>
          <h1>
            Know what got fixed.
            <br />
            Prove it to the board.
          </h1>
          <p>
            Fixed, introduced, SLA and MTTR across every org — from a CSV or
            your Snyk data.
          </p>
          <small>One command. Your browser. Your data.</small>
        </section>
      </div>
    </div>
  );
}
