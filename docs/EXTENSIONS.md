# Add datasets, metrics and API adapters

## Register a dataset

Built-ins are `issues`, `usage`, `pr_checks`, `pr_checks_project_adoption`, `pr_checks_integration_adoption`, and `prevention_events`.

For another Export API dataset, supply a registry file or paste this into **Data & metrics → Register another dataset**:

```json
[
  {"name":"my_dataset","label":"My dataset","dateFilter":"updated"}
]
```

`name` is the exact dataset identifier supported by your API, or a local CSV dataset name. `dateFilter` must be `introduced`, `updated` or `event`. This is configuration, not discovery: verify the actual dataset/schema and entitlements. Registry names must be unique; built-ins cannot be overwritten.

```sh
node pulse.mjs --registry ./datasets.json --dataset my_dataset=./data.csv
node pulse.mjs --registry ./datasets.json --org YOUR_ORG_UUID --datasets issues,my_dataset
```

The issues endpoint and all generic datasets share the export transport. Registering an arbitrary URL is not supported. This prevents passing Snyk tokens to unintended hosts.

## Define metrics

Load a JSON array with `--metrics ./metrics.json`, or edit/upload it in **Data & metrics**. Applying replaces the custom definitions for this session. Use **Save definitions file** to reuse them on the next run.

```json
[
  {
    "id":"critical_open",
    "label":"Critical open",
    "dataset":"issues",
    "window":"snapshot",
    "aggregate":"count",
    "where":[
      {"field":"ISSUE_STATUS","op":"eq","value":"Open"},
      {"field":"ISSUE_SEVERITY","op":"eq","value":"Critical"}
    ]
  },
  {
    "id":"events_per_project",
    "label":"Projects with events",
    "dataset":"my_dataset",
    "window":"period",
    "dateField":"EVENT_DATE",
    "aggregate":"distinct",
    "field":"PROJECT_ID",
    "scopeFields":{"org_id":"ORG_ID","project_id":"PROJECT_ID"}
  },
  {
    "id":"pass_rate",
    "label":"Pass rate",
    "dataset":"my_dataset",
    "window":"period",
    "dateField":"EVENT_DATE",
    "aggregate":"percentage",
    "numerator":[{"field":"RESULT","op":"eq","value":"passed"}],
    "unit":"%",
    "scopeFields":{"org_id":"ORG_ID"}
  }
]
```

`EVENT_DATE`, `PROJECT_ID`, `ORG_ID`, and `RESULT` here are illustrative columns. Inspect **Available columns** on your loaded dataset and use its real normalized names.

- `count`: rows matching `where`.
- `distinct`: distinct nonempty values of `field`.
- `sum`, `mean`: numeric `field`; missing/non-numeric values make the metric unavailable.
- `percentage`: rows matching `numerator` divided by rows matching `where`, ×100. Empty denominators are unavailable.
- Predicates: `eq`, `ne`, `in`, `gt`, `gte`, `lt`, `lte`, `present`; all rules in a list must match. Equality is case-insensitive.
- `window: period` requires `dateField` and uses the dashboard UTC date range. `snapshot` uses all loaded rows.
- Default scope mappings: `ORG_PUBLIC_ID`, `PROJECT_PUBLIC_ID`, `GROUP_DISPLAY_NAME`, `PRODUCT_NAME`, `ISSUE_SEVERITY`. Override with `scopeFields`.
- Missing dataset, required columns, invalid event dates or an unmappable active filter produce an unavailable card with a reason.
- Issue rows have already been deduplicated and deletion-filtered. Other datasets retain their CSV row grain; choose the correct count/distinct semantics.
- Definitions are interpreted as data. No JavaScript expressions or `eval` are accepted.

Custom metrics appear on persona dashboards, in Data & metrics, the dictionary and standard metric CSV exports. Their values follow active filters and periods. The built-in explorer groups the normalized issues metrics; it does not infer group mappings for custom datasets.

## Add a dedicated JavaScript API adapter

The stable boundary is an async collector returning `Map<datasetName, {headers, rows}>`, where each row maps normalized column names to values:

```js
export async function collectInventory(options, {signal, onProgress}) {
  // Use an explicit allowlisted API origin, validate scope, paginate and honor signal.
  // Fetch with the right authentication; never log it or return it in rows.
  const rows = await readInventoryPages(options, signal); // implement for your API
  onProgress({stage: 'complete', message: 'Inventory loaded.'});
  return new Map([['inventory', {
    headers: ['ORG_PUBLIC_ID', 'PROJECT_PUBLIC_ID', 'LAST_TESTED'],
    rows
  }]]);
}
```

This is an adapter skeleton, not a working route. `lib/snyk.mjs` is the working export adapter to follow. Register the output dataset, then wire a collector dispatch into `pulse.mjs` and `lib/server.mjs`. Both use `addDatasets` from `lib/session.mjs` for atomic ingestion; `startServer` and CLI `main` accept injected `pull` functions for tests. Keep arbitrary network URLs out of metric JSON.

Tests should cover the target API’s real schema fixtures, pagination, timeouts/cancellation, token redaction, scope enforcement and normalized output. No UI or metric-engine changes are required for additional tabular datasets once the collector and definitions are present.
