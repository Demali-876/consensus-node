import type { ProxyRequestMessage, ProxyResponseMessage } from "../tunnel/messages";
import { MESSAGE_TYPE, nowSeconds } from "../tunnel/messages";

export function isBlockedProxyUrl(urlStr: string): boolean {
  let raw: string;
  try {
    raw = new URL(urlStr).hostname.toLowerCase();
  } catch {
    return true;
  }
  // Strip IPv6 brackets so all checks work on the bare address.
  const host = raw.startsWith("[") && raw.endsWith("]") ? raw.slice(1, -1) : raw;
  return (
    host === "localhost" ||
    /^127\./.test(host) ||
    /^10\./.test(host) ||
    /^172\.(1[6-9]|2\d|30|31)\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^169\.254\./.test(host) ||
    host === "::1" ||
    /^fe80:/i.test(host) ||
    /^fc[0-9a-f]{2}:/i.test(host) ||
    /^fd[0-9a-f]{2}:/i.test(host)
  );
}

export async function executeProxyCommand(message: ProxyRequestMessage): Promise<ProxyResponseMessage> {
  if (isBlockedProxyUrl(message.target_url)) {
    throw new Error(`Proxy request blocked: target URL resolves to a private or reserved address`);
  }
  const method = (message.method || "GET").toUpperCase();
  const start = performance.now();
  const body = decodeBody(message.body, message.body_encoding);

  const response = await fetch(message.target_url, {
    method,
    headers: {
      ...(message.headers || {}),
      "user-agent": "Consensus-Node/0.1",
    },
    body: method === "GET" || method === "HEAD" ? undefined : body,
    signal: AbortSignal.timeout(30_000),
  });

  const responseBody = Buffer.from(await response.arrayBuffer());

  return {
    type: MESSAGE_TYPE.PROXY_RESPONSE,
    timestamp: nowSeconds(),
    reply_to: message.id ?? "",
    status: response.status,
    status_text: response.statusText,
    headers: Object.fromEntries(response.headers.entries()),
    body: responseBody.toString("base64"),
    body_encoding: "base64",
  };
}

function decodeBody(body: string | undefined, encoding: "utf8" | "base64" | undefined): string | Buffer | undefined {
  if (body == null) return undefined;
  if (encoding === "base64") return Buffer.from(body, "base64");
  return body;
}
