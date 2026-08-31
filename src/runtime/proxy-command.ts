import type { ProxyRequestMessage, ProxyResponseMessage } from "../tunnel/messages";
import { MESSAGE_TYPE, nowSeconds } from "../tunnel/messages";
import { serveProxyRequest } from "./proxy-serve";

export async function executeProxyCommand(message: ProxyRequestMessage): Promise<ProxyResponseMessage> {
  const method = (message.method || "GET").toUpperCase();
  const body = decodeBody(message.body, message.body_encoding);
  const response = await serveProxyRequest({
    target_url: message.target_url,
    method,
    headers: message.headers,
    body,
    profile: message.profile,
  });

  return {
    type: MESSAGE_TYPE.PROXY_RESPONSE,
    timestamp: nowSeconds(),
    reply_to: message.id ?? "",
    status: response.status,
    status_text: response.statusText,
    headers: response.headers,
    body: response.body.toString("base64"),
    body_encoding: "base64",
    cached: response.cached,
    profile_hash: response.profile_hash,
  };
}

function decodeBody(body: string | undefined, encoding: "utf8" | "base64" | undefined): string | Buffer | undefined {
  if (body == null) return undefined;
  if (encoding === "base64") return Buffer.from(body, "base64");
  return body;
}
