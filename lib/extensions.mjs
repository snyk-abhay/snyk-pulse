import { validDay, timestamp } from "./csv.mjs";

export const BUILTIN_DATASETS = Object.freeze({
  issues: { name: "issues", label: "Issues", dateFilter: "introduced" },
  usage: { name: "usage", label: "Usage events", dateFilter: "updated" },
  pr_checks: { name: "pr_checks", label: "PR checks", dateFilter: "updated" },
  pr_checks_project_adoption: {
    name: "pr_checks_project_adoption",
    label: "PR checks · project adoption",
    dateFilter: "updated",
  },
  pr_checks_integration_adoption: {
    name: "pr_checks_integration_adoption",
    label: "PR checks · integration adoption",
    dateFilter: "updated",
  },
  prevention_events: {
    name: "prevention_events",
    label: "Prevention events",
    dateFilter: "event",
  },
});
const pattern = /^[a-z][a-z0-9_]{0,63}$/;
const operators = new Set([
  "eq",
  "ne",
  "in",
  "gt",
  "gte",
  "lt",
  "lte",
  "present",
]);

export function datasetRegistry(extra = []) {
  if (!Array.isArray(extra))
    throw new Error("Dataset definitions must be an array.");
  const registry = structuredClone(BUILTIN_DATASETS);
  for (const item of extra) {
    if (!item || !pattern.test(item.name) || Object.hasOwn(registry, item.name))
      throw new Error(
        "Dataset names must be unique lowercase identifiers; built-in names cannot be overridden.",
      );
    if (!["introduced", "updated", "event"].includes(item.dateFilter))
      throw new Error(
        "Dataset dateFilter must be introduced, updated or event.",
      );
    registry[item.name] = {
      name: item.name,
      label: String(item.label || item.name).slice(0, 120),
      dateFilter: item.dateFilter,
    };
  }
  return registry;
}

export function validateMetrics(definitions, registry) {
  if (!Array.isArray(definitions) || definitions.length > 100)
    throw new Error("Metrics must be an array with at most 100 definitions.");
  const ids = new Set();
  for (const m of definitions) {
    if (!m || !pattern.test(m.id) || ids.has(m.id))
      throw new Error("Metric IDs must be unique lowercase identifiers.");
    ids.add(m.id);
    if (!Object.hasOwn(registry, m.dataset))
      throw new Error(`Metric ${m.id} uses an unregistered dataset.`);
    if (
      !["count", "distinct", "sum", "mean", "percentage"].includes(m.aggregate)
    )
      throw new Error(
        `Metric ${m.id}: aggregate must be count, distinct, sum, mean or percentage.`,
      );
    if (!["snapshot", "period"].includes(m.window))
      throw new Error(`Metric ${m.id}: window must be snapshot or period.`);
    if (m.window === "period" && typeof m.dateField !== "string")
      throw new Error(`Metric ${m.id} needs a dateField.`);
    if (
      ["distinct", "sum", "mean"].includes(m.aggregate) &&
      typeof m.field !== "string"
    )
      throw new Error(`Metric ${m.id} needs a field.`);
    for (const rules of [m.where || [], m.numerator || []]) {
      if (!Array.isArray(rules) || rules.length > 25)
        throw new Error(`Metric ${m.id}: invalid predicate list.`);
      for (const r of rules) {
        if (!r || typeof r.field !== "string" || !operators.has(r.op))
          throw new Error(`Metric ${m.id}: invalid predicate.`);
        if (r.op === "in" && !Array.isArray(r.value))
          throw new Error(`Metric ${m.id}: 'in' needs an array.`);
        if (r.op !== "present" && r.value === undefined)
          throw new Error(`Metric ${m.id}: predicate value missing.`);
      }
    }
    if (m.aggregate === "percentage" && !m.numerator?.length)
      throw new Error(`Metric ${m.id}: percentage needs numerator predicates.`);
    if (
      m.scopeFields != null &&
      (typeof m.scopeFields !== "object" ||
        Array.isArray(m.scopeFields) ||
        Object.values(m.scopeFields).some((v) => typeof v !== "string"))
    )
      throw new Error(
        `Metric ${m.id}: scopeFields must map filters to CSV column names.`,
      );
  }
  return structuredClone(definitions);
}

function matches(row, rule) {
  const v = row[rule.field];
  switch (rule.op) {
    case "present":
      return v != null && String(v).trim() !== "";
    case "eq":
      return String(v).toLowerCase() === String(rule.value).toLowerCase();
    case "ne":
      return String(v).toLowerCase() !== String(rule.value).toLowerCase();
    case "in":
      return rule.value.some(
        (x) => String(x).toLowerCase() === String(v).toLowerCase(),
      );
    default: {
      const a = Number(v),
        b = Number(rule.value);
      if (
        v == null ||
        String(v).trim() === "" ||
        !Number.isFinite(a) ||
        !Number.isFinite(b)
      )
        return false;
      return rule.op === "gt"
        ? a > b
        : rule.op === "gte"
          ? a >= b
          : rule.op === "lt"
            ? a < b
            : a <= b;
    }
  }
}

export function computeExtensions(definitions, datasets, context) {
  return definitions.map((m) => {
    const result = {
      id: m.id,
      label: m.label || m.id,
      dataset: m.dataset,
      window: m.window,
      unit: m.unit || "",
      value: null,
      reason: null,
    };
    const data = datasets.get(m.dataset);
    if (!data) return { ...result, reason: `Load the ${m.dataset} dataset.` };
    const rules = [...(m.where || []), ...(m.numerator || [])];
    const scopeFields = {
      org_id: "ORG_PUBLIC_ID",
      project_id: "PROJECT_PUBLIC_ID",
      group: "GROUP_DISPLAY_NAME",
      product: "PRODUCT_NAME",
      severity: "ISSUE_SEVERITY",
      ...m.scopeFields,
    };
    const required = [
      ...rules.map((r) => r.field),
      ...(["sum", "mean", "distinct"].includes(m.aggregate) ? [m.field] : []),
      ...(m.window === "period" ? [m.dateField] : []),
      ...Object.entries(context.filters || {})
        .filter(([, v]) => v)
        .map(([k]) => scopeFields[k]),
    ];
    if (required.some((f) => !data.headers.includes(f)))
      return {
        ...result,
        reason: "Required columns or active filter mappings are missing.",
      };
    let rows = data.rows.filter((row) =>
      Object.entries(context.filters || {}).every(
        ([k, v]) =>
          !v ||
          String(row[scopeFields[k]]).toLowerCase() === String(v).toLowerCase(),
      ),
    );
    if (m.window === "period") {
      let dates;
      try {
        dates = rows.map((row) => {
          const date = timestamp(row[m.dateField]);
          if (!date) throw new Error("Missing date");
          return date.slice(0, 10);
        });
      } catch {
        return {
          ...result,
          reason: "Some rows have missing or invalid event dates.",
        };
      }
      const start = validDay(context.start),
        end = validDay(context.end);
      rows = rows.filter(
        (_, index) => dates[index] >= start && dates[index] <= end,
      );
    }
    rows = rows.filter((row) =>
      (m.where || []).every((rule) => matches(row, rule)),
    );
    if (m.aggregate === "count") result.value = rows.length;
    else if (m.aggregate === "distinct")
      result.value = new Set(
        rows.map((r) => r[m.field]).filter((v) => v != null && v !== ""),
      ).size;
    else if (m.aggregate === "percentage")
      result.value = rows.length
        ? (rows.filter((r) => m.numerator.every((rule) => matches(r, rule)))
            .length /
            rows.length) *
          100
        : null;
    else {
      if (
        rows.some(
          (r) =>
            r[m.field] == null ||
            String(r[m.field]).trim() === "" ||
            !Number.isFinite(Number(r[m.field])),
        )
      )
        return {
          ...result,
          reason: "Some rows have missing or non-numeric values.",
        };
      const total = rows.reduce((sum, r) => sum + Number(r[m.field]), 0);
      result.value =
        m.aggregate === "sum"
          ? total
          : rows.length
            ? total / rows.length
            : null;
    }
    if (result.value != null && !Number.isFinite(result.value))
      return {
        ...result,
        value: null,
        reason: "Aggregate exceeds numeric range.",
      };
    if (result.value != null)
      result.value = Math.round(result.value * 100) / 100;
    return result;
  });
}
