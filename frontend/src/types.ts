export type Policy = Record<"critical" | "high" | "medium" | "low", number>;
export type MetricDefinition = {
  id: string;
  label: string;
  dataset: string;
  window: "snapshot" | "period";
  aggregate: string;
  [key: string]: unknown;
};
export type CustomMetric = {
  id: string;
  label: string;
  dataset: string;
  window: string;
  value: number | null;
  unit: string;
  reason: string | null;
};
export type Job = {
  running: boolean;
  stage: string;
  message: string;
  dataset?: string;
  exportId?: string;
  canResume?: boolean;
  code?: string;
  failedStage?: string;
};
export type Snapshot = {
  id: number;
  source: string;
  as_of: string;
  imported_at: string;
  excluded_deleted: number;
  duplicates: number;
  warnings: string[];
};
export type SnykScope = { id: string; name: string; groupId?: string };
export type SnykConnection = {
  id: string;
  region: string;
  identity: {
    id: string;
    type: "user" | "service_account" | "app_instance";
    name: string;
  };
  groups: SnykScope[];
  orgs: SnykScope[];
  warnings: string[];
  validatedAt: string;
};
export type AppState = {
  snapshot: Snapshot | null;
  count: number;
  policy: Policy;
  options: Record<string, (string | { value: string; label: string })[]>;
  registry: { name: string; label: string; dateFilter: string }[];
  datasets: { name: string; rows: number; headers: string[]; source: string }[];
  definitions: MetricDefinition[];
  job: Job | null;
  hasToken: boolean;
  connectionRegion: string;
  version: number | null;
  workspaceName?: string | null;
  groupLookup?: { running: boolean; message: string | null; missing: number };
  store?: {
    enabled: boolean;
    location?: string;
    tokenSaved?: boolean;
    warning?: string | null;
    source?: SavedSource | null;
  };
};
export type SavedSource =
  | {
      kind: "api";
      region: string;
      org?: string;
      group?: string;
      datasets: string[];
      from: string;
      scopeName: string | null;
      pulledAt: string;
    }
  | {
      kind: "csv";
      dataset: string;
      fileName: string | null;
      asOf: string;
      importedAt: string;
    }
  | { kind: "demo" };
export type Version = {
  id: number;
  created_at: string;
  as_of: string;
  source: string;
  from: string | null;
  issues: number;
  datasets: { name: string; rows: number }[];
};
export type Issue = {
  key: string;
  problem_id: string;
  title: string;
  org: string;
  org_id: string;
  project: string;
  product: string;
  target: string;
  target_ref: string;
  issue_type: string;
  cve: string;
  cwe: string;
  severity: string;
  age_days: number;
  days_to_sla: number;
  over_sla: boolean;
  fixable: boolean | null;
  fix_version: string;
  package: string;
  exploitable: boolean | null;
  reachable: boolean | null;
};
export type Series = { name: string; value: number }[];
export type Dashboard = {
  snapshot: Snapshot;
  period: { start: string; end: string };
  policy: Policy;
  metrics: Record<string, number | null>;
  previous: Record<string, number | string>;
  trend: { date: string; introduced: number; fixed: number }[];
  severity: Series;
  aging: Series;
  sources: Series;
  fixed_products: Series;
  ranking: {
    org_id: string;
    org: string;
    open: number;
    over_sla: number;
    critical_high: number;
  }[];
  products: (Series[number] & { critical_high: number; over_sla: number })[];
  issue_types: Series;
  exploit_maturity: Series;
  cwes: Series;
  owasp: { name: string; value: number; critical_high: number }[];
  owasp_mapped: number;
  cves: Series;
  project_types: Series;
  repositories: {
    repo: string;
    org: string;
    open: number;
    critical_high: number;
    fixable: number;
    over_sla: number;
    projects: number;
    branches: string[];
  }[];
  repository_total: number;
  packages: {
    name: string;
    value: number;
    critical_high: number;
    fixable: number;
    repos: number;
    fix_version: string;
  }[];
  branches: Series;
  issues: Issue[];
  issue_total: number;
  notes: string[];
  custom_metrics: CustomMetric[];
};
