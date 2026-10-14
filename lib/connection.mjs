import { networkFailure } from "./network.mjs";

export const REGIONS = Object.freeze({
  us: "https://api.snyk.io",
  us01: "https://api.snyk.io",
  us02: "https://api.us.snyk.io",
  eu: "https://api.eu.snyk.io",
  au: "https://api.au.snyk.io",
  gov: "https://api.snykgov.io",
});
export const API_VERSION = "2024-10-15";
// The groups listing is published as beta, separately from the GA org APIs.
const GROUP_VERSION = "2023-01-30~beta";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function credentials(options) {
  let region = String(options.region || "us")
    .toLowerCase()
    .replaceAll("-", "");
  if (region === "us01") region = "us";
  if (!Object.hasOwn(REGIONS, region))
    throw new Error("Region must be us, us02, eu, au or gov.");
  if (
    typeof options.token !== "string" ||
    !options.token.trim() ||
    /[\r\n]/.test(options.token) ||
    options.token.length > 16_384
  )
    throw new Error(
      "Enter a Snyk personal or service-account token, or supply SNYK_TOKEN.",
    );
  const authScheme = options.authScheme || "token";
  if (!["token", "bearer"].includes(authScheme))
    throw new Error("Unsupported authentication scheme.");
  return {
    region,
    base: REGIONS[region],
    token: options.token.trim(),
    authScheme,
  };
}

function apiClient(config, { fetchImpl = fetch, signal } = {}) {
  const deadline = AbortSignal.timeout(60_000);
  const overall = signal ? AbortSignal.any([signal, deadline]) : deadline;
  let received = 0;
  return async (path, version = API_VERSION) => {
    // Only locally constructed REST paths are accepted. Pagination supplies
    // cursors, never a destination for an authenticated request.
    const url = new URL(path, config.base);
    if (
      url.origin !== config.base ||
      !url.pathname.startsWith("/rest/") ||
      url.username ||
      url.password
    )
      throw new Error("Snyk returned an unsafe discovery URL.");
    url.searchParams.set("version", version);
    let response;
    try {
      response = await fetchImpl(url, {
        redirect: "error",
        signal: overall,
        headers: {
          Authorization: `${config.authScheme} ${config.token}`,
          Accept: "application/vnd.api+json",
        },
      });
    } catch (error) {
      throw networkFailure(error, "Checking Snyk account access", overall);
    }
    if (!response.ok) {
      await response.body?.cancel();
      const messages = {
        401: "Snyk rejected this token. Check the region and whether the token is expired or revoked.",
        403: "Snyk denied access. Check this account’s permissions and API plan entitlement.",
        429: "Snyk is rate limiting requests. Wait a moment, then validate again.",
      };
      throw Object.assign(
        new Error(
          messages[response.status] ||
            `Snyk discovery failed (HTTP ${response.status}). Retry validation.`,
        ),
        { status: response.status },
      );
    }
    const chunks = [];
    let size = 0;
    for await (const chunk of response.body || []) {
      size += chunk.length;
      received += chunk.length;
      if (size > 2 * 1024 * 1024 || received > 20 * 1024 * 1024)
        throw new Error(
          "Snyk discovery response exceeds the utility size limit.",
        );
      chunks.push(chunk);
    }
    try {
      return JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      throw new Error("Snyk returned an invalid discovery response.");
    }
  };
}

async function list(api, config, path, label, version = API_VERSION) {
  const items = new Map(),
    warnings = [],
    cursors = new Set();
  let cursor = "";
  for (let page = 0; page < 100; page++) {
    const query = new URLSearchParams({ limit: "100" });
    if (cursor) query.set("starting_after", cursor);
    let result;
    try {
      result = await api(`${path}?${query}`, version);
    } catch (error) {
      if (error.status === 401) throw error;
      warnings.push(
        `${label} could not be fully listed. ${error.message} You can enter a known scope UUID instead.`,
      );
      break;
    }
    if (!Array.isArray(result.data))
      throw new Error(`Snyk returned an invalid ${label.toLowerCase()} list.`);
    for (const item of result.data) {
      if (!UUID.test(item?.id || "")) continue;
      items.set(item.id, {
        id: item.id,
        name: String(item.attributes?.name || item.id).slice(0, 300),
        ...(UUID.test(item.attributes?.group_id || "")
          ? { groupId: item.attributes.group_id }
          : {}),
      });
      if (items.size >= 10_000) break;
    }
    const next = result.links?.next;
    if (!next) break;
    const nextUrl = new URL(
      typeof next === "string" ? next : next.href,
      config.base,
    );
    // Reject redirects to other hosts/paths; copy only the documented cursor.
    if (
      nextUrl.origin !== config.base ||
      nextUrl.pathname !== path ||
      nextUrl.username ||
      nextUrl.password
    )
      throw new Error("Snyk returned an unsafe pagination link.");
    cursor = nextUrl.searchParams.get("starting_after");
    if (!cursor || cursor.length > 4096 || cursors.has(cursor))
      throw new Error("Snyk returned an invalid pagination cursor.");
    cursors.add(cursor);
    if (page === 99 || items.size >= 10_000) {
      warnings.push(
        `${label} discovery reached 10,000 entries / 100 pages. Enter a known UUID if your scope is missing.`,
      );
      break;
    }
  }
  return {
    items: [...items.values()].sort((a, b) => a.name.localeCompare(b.name)),
    warnings,
  };
}

export async function authenticate(options, dependencies = {}) {
  const config = credentials(options);
  // Legacy keys use token; OAuth access tokens use bearer. Probe /self only,
  // and try the alternate scheme solely after an explicit 401 response.
  let principal;
  try {
    principal = await apiClient(config, dependencies)("/rest/self");
  } catch (error) {
    if (error.status !== 401 || options.authScheme) throw error;
    config.authScheme = "bearer";
    principal = await apiClient(config, dependencies)("/rest/self");
  }
  const data = principal?.data;
  if (
    !UUID.test(data?.id || "") ||
    !["user", "service_account", "app_instance"].includes(data.type)
  )
    throw new Error(
      "Snyk did not return a valid account identity. Validation could not be completed.",
    );
  return {
    config,
    identity: {
      id: data.id,
      type: data.type,
      name: String(
        data.attributes?.name ||
          data.attributes?.username ||
          (data.type === "service_account"
            ? "Service account"
            : "Snyk account"),
      ).slice(0, 300),
    },
  };
}

export async function discoverConnection(options, dependencies = {}) {
  const { config, identity } = await authenticate(options, dependencies);
  const api = apiClient(config, dependencies);
  const groups = await list(
    api,
    config,
    "/rest/groups",
    "Groups",
    GROUP_VERSION,
  );
  const orgs = await list(api, config, "/rest/orgs", "Organizations");
  return {
    config,
    connection: {
      region: config.region,
      identity,
      groups: groups.items,
      orgs: orgs.items,
      warnings: [...groups.warnings, ...orgs.warnings],
      validatedAt: new Date().toISOString(),
    },
  };
}

export async function discoverGroupOrgs(options, groupId, dependencies = {}) {
  if (!UUID.test(groupId || "")) throw new Error("Provide a valid group UUID.");
  const config = credentials(options);
  const result = await list(
    apiClient(config, dependencies),
    config,
    `/rest/groups/${groupId}/orgs`,
    "Organizations in this group",
  );
  return {
    orgs: result.items.map((item) => ({ ...item, groupId })),
    warnings: result.warnings,
  };
}

/**
 * Map org IDs to their Snyk group (id and name) for exports without group
 * columns. Uses the org and group listings the token can see; orgs it cannot
 * see are simply left unmapped.
 */
export async function resolveGroups(options, orgIds, dependencies = {}) {
  const { config } = await authenticate(options, dependencies);
  const api = apiClient(config, dependencies);
  const [orgs, groups] = await Promise.all([
    list(api, config, "/rest/orgs", "Organizations"),
    list(api, config, "/rest/groups", "Groups", GROUP_VERSION),
  ]);
  const names = new Map(groups.items.map((g) => [g.id, g.name]));
  const wanted = new Set(orgIds);
  const mapping = {};
  for (const org of orgs.items)
    if (wanted.has(org.id) && org.groupId)
      mapping[org.id] = {
        id: org.groupId,
        name: names.get(org.groupId) || org.groupId,
      };
  return { config, mapping, warnings: [...orgs.warnings, ...groups.warnings] };
}
