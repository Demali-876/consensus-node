import type { ProxyRequestMessage, ProxyResponseMessage } from "../tunnel/messages";
import { MESSAGE_TYPE, nowSeconds } from "../tunnel/messages";

const MAX_PROXY_RESPONSE_BYTES = 50 * 1024 * 1024; // 50 MB

export async function executeProxyCommand(message: ProxyRequestMessage): Promise<ProxyResponseMessage> {
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

  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    const cl = parseInt(contentLength, 10);
    if (Number.isFinite(cl) && cl > MAX_PROXY_RESPONSE_BYTES) {
      throw new Error(
        `Proxy response too large: content-length ${cl} bytes exceeds limit of ${MAX_PROXY_RESPONSE_BYTES} bytes`,
      );
    }
  }
  const responseBody = Buffer.from(await response.arrayBuffer());
  if (responseBody.length > MAX_PROXY_RESPONSE_BYTES) {
    throw new Error(
      `Proxy response too large: ${responseBody.length} bytes exceeds limit of ${MAX_PROXY_RESPONSE_BYTES} bytes`,
    );
  }

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
