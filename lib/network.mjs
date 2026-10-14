const descriptions = {
  ECONNRESET: "The connection was reset",
  EPIPE: "The connection closed while sending data",
  UND_ERR_SOCKET: "The remote connection closed unexpectedly",
  ETIMEDOUT: "The request timed out",
  UND_ERR_CONNECT_TIMEOUT: "Connecting to the server timed out",
  UND_ERR_HEADERS_TIMEOUT: "The server took too long to respond",
  UND_ERR_BODY_TIMEOUT: "The download stalled",
  ENOTFOUND: "DNS could not resolve the server",
  EAI_AGAIN: "DNS lookup temporarily failed",
  ECONNREFUSED: "The server refused the connection",
  ENETUNREACH: "The network is unreachable",
  EHOSTUNREACH: "The server is unreachable",
  Z_DATA_ERROR: "The server returned an invalid compressed response",
  Z_BUF_ERROR: "The compressed response ended unexpectedly",
  UND_ERR_RESPONSE_CONTENT_LENGTH_MISMATCH:
    "The response ended before its declared length",
  UND_ERR_HEADERS_OVERFLOW:
    "The server response headers exceeded the supported size",
  UNEXPECTED_REDIRECT:
    "The server redirected the request; automatic redirect following was blocked",
};
const certificateCodes = new Set([
  "SELF_SIGNED_CERT_IN_CHAIN",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "CERT_HAS_EXPIRED",
  "ERR_TLS_CERT_ALTNAME_INVALID",
]);

export function networkFailure(error, operation, signal) {
  if (signal?.aborted) {
    const timedOut = signal.reason?.name === "TimeoutError";
    return Object.assign(
      new Error(
        timedOut
          ? `${operation}: the export time limit was reached. Resume the existing export after checking your connection.`
          : "Export cancelled.",
      ),
      { code: timedOut ? "EXPORT_TIMEOUT" : "CANCELLED", retryable: false },
    );
  }
  const pending = [error],
    seen = new Set();
  let code = "NETWORK_ERROR";
  for (let i = 0; pending.length && i < 12; i++) {
    const current = pending.shift();
    if (!current || typeof current !== "object" || seen.has(current)) continue;
    seen.add(current);
    if (current.message === "unexpected redirect") {
      code = "UNEXPECTED_REDIRECT";
      break;
    }
    if (
      certificateCodes.has(current.code) ||
      Object.hasOwn(descriptions, current.code)
    ) {
      code = current.code;
      break;
    }
    if (["TimeoutError", "AbortError"].includes(current.name))
      code = "ETIMEDOUT";
    pending.push(
      current.cause,
      ...(Array.isArray(current.errors) ? current.errors.slice(0, 4) : []),
    );
  }
  // Never echo raw errors: they may contain Authorization headers or signed URLs.
  const certificate = certificateCodes.has(code);
  return Object.assign(
    new Error(
      certificate
        ? `${operation}: TLS certificate verification failed (${code}). Configure your company's trusted CA using NODE_EXTRA_CA_CERTS, then restart Pulse. Certificate verification remains enabled.`
        : `${operation}: ${descriptions[code] || "the network request failed"} (${code}). Check your network, VPN or proxy, then resume the existing export if available.`,
    ),
    { code, retryable: !certificate && code !== "UNEXPECTED_REDIRECT" },
  );
}
