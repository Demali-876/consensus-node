// Blocks SSRF by rejecting URLs that resolve to private/internal networks.
// Both the HTTP proxy endpoint and the encrypted-tunnel proxy command use this.

const BLOCKED_HOSTS = new Set(["localhost"]);

// Covers RFC 1918, loopback, link-local (cloud metadata), and IPv6 equivalents.
const PRIVATE_HOST_PATTERNS = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^169\.254\./,    // AWS/GCP/Azure metadata service
  /^0\./,           // "this" network
  /^::1$/,          // IPv6 loopback
  /^fc[0-9a-f]{2}:/i,
  /^fd[0-9a-f]{2}:/i,
  /^fe80:/i,
];

const ALLOWED_SCHEMES = new Set(["http:", "https:"]);

/**
 * Returns true when the URL should NOT be forwarded by the proxy.
 * An unparseable URL, a non-http(s) scheme, or a private/internal host
 * all return true.
 */
export function isBlockedProxyUrl(rawUrl: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return true;
  }

  if (!ALLOWED_SCHEMES.has(parsed.protocol)) return true;

  const host = parsed.hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(host)) return true;

  for (const pattern of PRIVATE_HOST_PATTERNS) {
    if (pattern.test(host)) return true;
  }

  return false;
}
