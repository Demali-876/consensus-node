import { spawn } from "node:child_process";
import { randomInt, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

export interface WalletAddresses {
  evmAddress?: string;
  solanaAddress?: string;
  icpAddress?: string;
}

export type WalletAddressErrors = Partial<Record<keyof WalletAddresses, string>>;

export interface WalletAddressServerOptions {
  host?: string;
  port?: number;
  initialAddresses?: WalletAddresses;
}

export interface WalletAddressSession {
  url: string;
  done: Promise<WalletAddresses>;
  stop: () => Promise<void>;
}

const DEFAULT_HOST = "127.0.0.1";
const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const EVM_RE = /^0x[a-fA-F0-9]{40}$/;
const ICP_PRINCIPAL_RE = /^[a-z0-9]{1,5}(?:-[a-z0-9]{1,5})+$/;
const ASSETS = new Map([
  ["/assets/consensus-logo-light.svg", new URL("./assets/consensus-logo-light.svg", import.meta.url)],
  ["/assets/consensus-logo-dark.svg", new URL("./assets/consensus-logo-dark.svg", import.meta.url)],
  ["/assets/phantom.svg", new URL("./assets/phantom.svg", import.meta.url)],
  ["/assets/plug.jpeg", new URL("./assets/plug.jpeg", import.meta.url)],
]);

export async function startWalletAddressServer(options: WalletAddressServerOptions = {}): Promise<WalletAddressSession> {
  const token = randomUUID();
  const host = options.host ?? DEFAULT_HOST;
  const initialAddresses = normalizeWalletAddresses(options.initialAddresses ?? {});
  let settled = false;
  let resolveDone!: (addresses: WalletAddresses) => void;
  let rejectDone!: (error: Error) => void;
  const done = new Promise<WalletAddresses>((resolve, reject) => {
    resolveDone = resolve;
    rejectDone = reject;
  });

  const server = http.createServer((request, response) => {
    handleNodeRequest(request, response, async (method, url, body) => {
      return await handleWalletRequest({
        method,
        url,
        body,
        token,
        initialAddresses,
        resolveDone: (addresses) => {
          if (!settled) {
            settled = true;
            resolveDone(addresses);
          }
        },
      });
    }).catch((error) => {
      sendNodeResponse(response, jsonResponse({
        error: error instanceof Error ? error.message : "Wallet address server failed",
      }, 500)).catch(() => {});
    });
  });

  const port = await listen(server, options.port, host);
  const url = `http://${host}:${port}/?token=${encodeURIComponent(token)}`;
  return {
    url,
    done,
    stop: async () => {
      if (!settled) {
        settled = true;
        rejectDone(new Error("Wallet address capture stopped before submission"));
      }
      await closeServer(server);
    },
  };
}

async function handleWalletRequest(input: {
  method: string;
  url: URL;
  body: unknown;
  token: string;
  initialAddresses: WalletAddresses;
  resolveDone: (addresses: WalletAddresses) => void;
}): Promise<Response> {
  const url = input.url;
  if (url.pathname === "/favicon.ico") return new Response(null, { status: 204 });
  if (url.searchParams.get("token") !== input.token) {
    return jsonResponse({ error: "Invalid wallet capture token" }, 403);
  }

  if (input.method === "GET" && ASSETS.has(url.pathname)) {
    return assetResponse(url.pathname);
  }

  if (input.method === "GET") {
    return htmlResponse(renderWalletAddressHtml({
      initialAddresses: input.initialAddresses,
      startPage: pageFromPath(url.pathname),
      submitUrl: `/capture?token=${encodeURIComponent(input.token)}`,
      lightLogoUrl: `/assets/consensus-logo-light.svg?token=${encodeURIComponent(input.token)}`,
      phantomLogoUrl: `/assets/phantom.svg?token=${encodeURIComponent(input.token)}`,
      plugLogoUrl: `/assets/plug.jpeg?token=${encodeURIComponent(input.token)}`,
    }));
  }

  if (input.method === "POST" && url.pathname === "/capture") {
    const addresses = normalizeWalletAddresses(input.body);
    const errors = validateWalletAddresses(addresses);
    if (Object.keys(errors).length > 0) {
      return jsonResponse({ error: "Invalid wallet address", errors }, 422);
    }
    if (!addresses.evmAddress && !addresses.solanaAddress && !addresses.icpAddress) {
      return jsonResponse({ error: "Connect at least one wallet before submitting" }, 400);
    }
    input.resolveDone(addresses);
    return jsonResponse({ success: true });
  }

  return jsonResponse({ error: "Not found" }, 404);
}

async function handleNodeRequest(
  request: IncomingMessage,
  response: ServerResponse,
  handler: (method: string, url: URL, body: unknown) => Promise<Response>,
): Promise<void> {
  const method = request.method ?? "GET";
  const host = request.headers.host ?? DEFAULT_HOST;
  const url = new URL(request.url ?? "/", `http://${host}`);
  const body = method === "POST" ? await readJsonBody(request) : null;
  const walletResponse = await handler(method, url, body);
  await sendNodeResponse(response, walletResponse);
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buffer.length;
    if (total > 64 * 1024) throw new Error("Request body too large");
    chunks.push(buffer);
  }
  if (chunks.length === 0) return null;
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    return null;
  }
}

async function sendNodeResponse(response: ServerResponse, walletResponse: Response): Promise<void> {
  const headers: Record<string, string> = {};
  walletResponse.headers.forEach((value, key) => {
    headers[key] = value;
  });
  response.writeHead(walletResponse.status, headers);
  if (!walletResponse.body) {
    response.end();
    return;
  }
  const body = Buffer.from(await walletResponse.arrayBuffer());
  response.end(body);
}

async function listen(server: http.Server, requestedPort: number | undefined, host: string): Promise<number> {
  const maxAttempts = requestedPort ? 1 : 20;
  let lastError: unknown;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const port = requestedPort ?? randomLocalPort();
    try {
      await listenOnce(server, port, host);
      const address = server.address() as AddressInfo;
      return address.port;
    } catch (error) {
      lastError = error;
      if (requestedPort || !isAddressInUse(error)) throw error;
    }
  }
  throw lastError instanceof Error ? lastError : new Error("Unable to start wallet address server");
}

async function listenOnce(server: http.Server, port: number, host: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const cleanup = () => server.off("error", onError);
    const onError = (error: Error) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    server.once("error", onError);
    server.listen(port, host, () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve();
    });
  });
}

function randomLocalPort(): number {
  return randomInt(45_000, 60_000);
}

function isAddressInUse(error: unknown): boolean {
  const code = error && typeof error === "object" ? (error as { code?: unknown }).code : undefined;
  return code === "EADDRINUSE" || String(error).includes("EADDRINUSE");
}

async function closeServer(server: http.Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

export async function openWalletAddressPage(url: string): Promise<void> {
  const command = browserOpenCommand(url);
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const child = spawn(command.command, command.args, {
      detached: true,
      stdio: "ignore",
    });
    child.once("spawn", () => {
      if (settled) return;
      settled = true;
      child.unref();
      resolve();
    });
    child.once("error", (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    });
  });
}

export function normalizeWalletAddresses(input: unknown): WalletAddresses {
  const record = input && typeof input === "object" ? input as Record<string, unknown> : {};
  return {
    evmAddress: normalizedText(record.evmAddress),
    solanaAddress: normalizedText(record.solanaAddress),
    icpAddress: normalizedText(record.icpAddress),
  };
}

export function mergeWalletAddresses(base: WalletAddresses, patch: WalletAddresses): WalletAddresses {
  return {
    evmAddress: patch.evmAddress ?? base.evmAddress,
    solanaAddress: patch.solanaAddress ?? base.solanaAddress,
    icpAddress: patch.icpAddress ?? base.icpAddress,
  };
}

export function validateWalletAddresses(addresses: WalletAddresses): WalletAddressErrors {
  const errors: WalletAddressErrors = {};
  if (addresses.evmAddress && !isValidEvmAddress(addresses.evmAddress)) {
    errors.evmAddress = "EVM address must be 0x followed by 40 hex characters";
  }
  if (addresses.solanaAddress && !isValidSolanaAddress(addresses.solanaAddress)) {
    errors.solanaAddress = "Solana address must be a base58 public key";
  }
  if (addresses.icpAddress && !isValidIcpAddress(addresses.icpAddress)) {
    errors.icpAddress = "ICP address must be a textual principal";
  }
  return errors;
}

export function isValidEvmAddress(value: string): boolean {
  return EVM_RE.test(value);
}

export function isValidSolanaAddress(value: string): boolean {
  return BASE58_RE.test(value);
}

export function isValidIcpAddress(value: string): boolean {
  return ICP_PRINCIPAL_RE.test(value);
}

function normalizedText(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

function pageFromPath(pathname: string): string {
  const value = pathname.replace(/^\/+/, "");
  return ["metamask", "phantom", "plug", "review"].includes(value) ? value : "overview";
}

function browserOpenCommand(url: string): { command: string; args: string[] } {
  if (process.platform === "darwin") return { command: "open", args: [url] };
  if (process.platform === "win32") return { command: "cmd", args: ["/c", "start", "", url] };
  return { command: "xdg-open", args: [url] };
}

function htmlResponse(body: string): Response {
  return new Response(body, {
    headers: {
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; img-src 'self' data:; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "content-type": "text/html; charset=utf-8",
      "x-content-type-options": "nosniff",
    },
  });
}

async function assetResponse(pathname: string): Promise<Response> {
  const asset = ASSETS.get(pathname);
  if (!asset) return jsonResponse({ error: "Not found" }, 404);
  const body = await readFile(asset);
  return new Response(body, {
    headers: {
      "cache-control": "no-store",
      "content-type": pathname.endsWith(".jpeg") ? "image/jpeg" : "image/svg+xml; charset=utf-8",
      "x-content-type-options": "nosniff",
    },
  });
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
    },
  });
}

function renderWalletAddressHtml(input: {
  initialAddresses: WalletAddresses;
  startPage: string;
  submitUrl: string;
  lightLogoUrl: string;
  phantomLogoUrl: string;
  plugLogoUrl: string;
}): string {
  return renderConsensusWalletAddressHtml(input);
}

function renderConsensusWalletAddressHtml(input: {
  initialAddresses: WalletAddresses;
  startPage: string;
  submitUrl: string;
  lightLogoUrl: string;
  phantomLogoUrl: string;
  plugLogoUrl: string;
}): string {
  const config = safeScriptJson(input);
  const phantomMark = `<img src="${input.phantomLogoUrl}" alt="">`;
  const plugMark = `<img src="${input.plugLogoUrl}" alt="">`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Consensus - Connect Payout Wallets</title>
<style>
  *{box-sizing:border-box}
  html{scroll-behavior:smooth}
  body{margin:0;background:#000;color:#fff;font-family:"Space Grotesk",Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;min-height:100vh}
  ::selection{background:rgba(255,255,255,0.16)}
  button,input{font:inherit}
  @keyframes cs-pulse{0%{box-shadow:0 0 0 0 rgba(2,113,235,0.55)}70%{box-shadow:0 0 0 7px rgba(2,113,235,0)}100%{box-shadow:0 0 0 0 rgba(2,113,235,0)}}
  @keyframes cs-spin{to{transform:rotate(360deg)}}
  @keyframes cs-in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
  .mono{font-family:"JetBrains Mono","SFMono-Regular",Consolas,ui-monospace,monospace}
  .page{position:relative;min-height:100vh;overflow:hidden}
  .grid-bg{position:absolute;inset:0;background-image:linear-gradient(rgba(255,255,255,0.045) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,0.045) 1px,transparent 1px);background-size:62px 62px;-webkit-mask-image:radial-gradient(ellipse 78% 55% at 50% 0%,#000 32%,transparent 76%);mask-image:radial-gradient(ellipse 78% 55% at 50% 0%,#000 32%,transparent 76%);pointer-events:none}
  .mark-spin{position:absolute;top:-180px;right:-160px;width:560px;height:560px;opacity:0.045;animation:cs-spin 150s linear infinite;pointer-events:none;background:url("${input.lightLogoUrl}") center/contain no-repeat}
  header.nav{position:sticky;top:0;z-index:80;backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);background:rgba(0,0,0,0.55);border-bottom:1px solid rgba(255,255,255,0.07)}
  header.nav nav{max-width:1180px;margin:0 auto;padding:13px 28px;display:flex;align-items:center;gap:14px}
  .brand{display:flex;align-items:center;gap:10px;text-decoration:none;color:#fff}
  .brand img{width:30px;height:30px;display:block;flex:none}
  .brand .word{font-weight:600;font-size:17px;letter-spacing:0}
  .live-badge{display:inline-flex;align-items:center;gap:7px;font-family:"JetBrains Mono","SFMono-Regular",Consolas,ui-monospace,monospace;font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:rgba(255,255,255,0.58);border:1px solid rgba(255,255,255,0.12);border-radius:999px;padding:5px 11px;margin-left:auto}
  .live-badge .d{width:6px;height:6px;border-radius:50%;background:#0271EB;animation:cs-pulse 2.4s infinite}
  main{position:relative;max-width:1180px;margin:0 auto;padding:64px 28px 90px}
  .toprow{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;flex-wrap:wrap}
  h1{margin:0 0 12px;font-size:clamp(30px,4vw,44px);line-height:1.05;letter-spacing:0;font-weight:600;max-width:20ch}
  .sub{margin:0 0 36px;font-size:16px;line-height:1.6;color:rgba(255,255,255,0.58);max-width:64ch}
  .sub .em{color:rgba(255,255,255,0.88)}
  .steplink{display:inline-flex;align-items:center;gap:8px;text-decoration:none;font-size:13px;color:rgba(255,255,255,0.6);border:1px solid rgba(255,255,255,0.14);border-radius:999px;padding:8px 16px;white-space:nowrap;transition:border-color .2s ease,color .2s ease;background:transparent;cursor:pointer}
  .steplink:hover{border-color:rgba(255,255,255,0.35);color:#fff}
  .tabs{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:34px 0 28px}
  .tab{font-family:inherit;font-size:14.5px;font-weight:500;color:rgba(255,255,255,0.62);background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.1);border-radius:11px;padding:13px 10px;cursor:pointer;text-align:center;transition:border-color .2s ease,color .2s ease,background .2s ease;display:flex;align-items:center;justify-content:center;gap:8px;min-width:0}
  .tab .tdot{width:6px;height:6px;border-radius:50%;background:rgba(255,255,255,0.2);flex:none}
  .tab.done .tdot{background:#2ecc8f}
  .tab:hover{border-color:rgba(255,255,255,0.24);color:#fff}
  .tab.on{color:#000;background:#fff;border-color:#fff;font-weight:600}
  .tab.on .tdot{background:#000}
  .cards{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;width:100%;overflow:visible}
  .card{min-width:0;border:1px solid rgba(255,255,255,0.1);border-radius:16px;background:rgba(255,255,255,0.018);padding:26px;display:flex;flex-direction:column;gap:16px;transition:border-color .25s ease,transform .25s ease;animation:cs-in .5s cubic-bezier(.2,.7,.2,1) both}
  .card:hover{border-color:rgba(255,255,255,0.22)}
  .card.connected{border-color:rgba(46,204,143,0.35)}
  .card-head{display:flex;align-items:flex-start;gap:14px}
  .card-head>div{min-width:0}
  .wicon{width:42px;height:42px;border-radius:11px;flex:none;display:flex;align-items:center;justify-content:center}
  .wicon svg{width:27px;height:27px;display:block}
  .wicon img{width:27px;height:27px;display:block;object-fit:contain}
  .wicon.icp img{width:30px;height:30px;border-radius:8px}
  .wicon.evm{background:linear-gradient(135deg,#f6851b33,#f6851b0d);border:1px solid #f6851b40}
  .wicon.sol{background:linear-gradient(135deg,#ab9ff233,#ab9ff20d);border:1px solid #ab9ff240}
  .wicon.icp{background:linear-gradient(135deg,#0271EB33,#0271EB0d);border:1px solid #0271EB40}
  .card-title{font-size:18px;font-weight:600;letter-spacing:0;margin:0 0 3px}
  .card-desc{margin:0;font-size:13px;color:rgba(255,255,255,0.5);line-height:1.5}
  .field{display:flex;flex-direction:column;gap:8px}
  .field-label{font-family:"JetBrains Mono","SFMono-Regular",Consolas,ui-monospace,monospace;font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:rgba(255,255,255,0.4)}
  .addr-box{min-width:0;max-width:100%;overflow:hidden;display:flex;align-items:center;gap:8px;border:1px solid rgba(255,255,255,0.12);border-radius:10px;background:#0a0a0b;padding:11px 12px;font-family:"JetBrains Mono","SFMono-Regular",Consolas,ui-monospace,monospace;font-size:12.5px;color:rgba(255,255,255,0.55);min-height:42px}
  .addr-box.filled{color:rgba(255,255,255,0.9)}
  .addr-box .atext{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .addr-box .copy{background:transparent;border:0;color:rgba(255,255,255,0.4);cursor:pointer;padding:2px;flex:none;transition:color .15s ease}
  .addr-box .copy:hover{color:#fff}
  .wallet-actions{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px}
  .btn-connect{width:100%;min-width:0;font-family:inherit;font-size:14.5px;font-weight:600;border:0;border-radius:10px;padding:12px 18px;cursor:pointer;color:#000;background:#fff;display:inline-flex;align-items:center;justify-content:center;gap:9px;transition:transform .15s ease,box-shadow .15s ease,background .15s ease,color .15s ease}
  .btn-connect:hover{transform:translateY(-1px);box-shadow:0 10px 30px rgba(255,255,255,0.12)}
  .btn-connect.connected{background:rgba(46,204,143,0.12);color:#2ecc8f;border:1px solid rgba(46,204,143,0.35)}
  .btn-connect.connected:hover{transform:none;box-shadow:none}
  .btn-connect.busy{opacity:0.6;cursor:wait}
  .btn-connect .spin{width:13px;height:13px;border-radius:50%;border:2px solid rgba(0,0,0,0.25);border-top-color:#000;animation:cs-spin .7s linear infinite;display:none}
  .btn-connect.busy .spin{display:inline-block}
  .btn-manual{border:1px solid rgba(255,255,255,0.14);border-radius:10px;padding:11px 14px;background:rgba(255,255,255,0.025);color:rgba(255,255,255,0.72);font-size:13px;font-weight:500;cursor:pointer;transition:border-color .15s ease,color .15s ease,background .15s ease}
  .btn-manual:hover,.btn-manual[aria-expanded="true"]{border-color:rgba(255,255,255,0.34);color:#fff;background:rgba(255,255,255,0.06)}
  .manual-entry{display:none;grid-template-columns:minmax(0,1fr) auto;gap:8px}
  .manual-entry.show{display:grid}
  .manual-input{min-width:0;width:100%;border:1px solid rgba(255,255,255,0.16);border-radius:10px;background:#0a0a0b;color:#fff;padding:10px 12px;font-family:"JetBrains Mono","SFMono-Regular",Consolas,ui-monospace,monospace;font-size:12px;outline:none}
  .manual-input::placeholder{color:rgba(255,255,255,0.28)}
  .manual-input:focus{border-color:rgba(2,113,235,0.75);box-shadow:0 0 0 3px rgba(2,113,235,0.12)}
  .manual-save{border:1px solid rgba(255,255,255,0.18);border-radius:10px;background:rgba(255,255,255,0.08);color:#fff;padding:10px 13px;font-size:12.5px;font-weight:600;cursor:pointer;white-space:nowrap}
  .manual-save:hover{background:rgba(255,255,255,0.13)}
  .status-line{display:flex;align-items:center;gap:8px;font-size:12.5px;min-height:16px}
  .status-line.ok{color:#2ecc8f}
  .status-line.err{color:#ff6b6b}
  .status-line.idle{color:rgba(255,255,255,0.38)}
  .status-line .sdot{width:6px;height:6px;border-radius:50%;background:currentColor;flex:none}
  .review-pane{display:none;border:1px solid rgba(255,255,255,0.1);border-radius:16px;background:rgba(255,255,255,0.018);padding:8px;animation:cs-in .4s ease both}
  .review-pane.show{display:block}
  .review-row{display:grid;grid-template-columns:150px minmax(0,1fr) 100px;gap:16px;align-items:center;padding:16px 18px;border-bottom:1px solid rgba(255,255,255,0.06)}
  .review-row:last-child{border-bottom:0}
  .review-row .rk{font-size:14px;font-weight:500;display:flex;align-items:center;gap:10px}
  .review-row .rk .ricon{width:24px;height:24px;border-radius:6px;flex:none;display:flex;align-items:center;justify-content:center}
  .review-row .rk .ricon svg{width:16px;height:16px;display:block}
  .review-row .rk .ricon img{width:16px;height:16px;display:block;object-fit:contain}
  .review-row .rk .ricon.icp img{border-radius:4px}
  .review-row .rv{min-width:0;font-family:"JetBrains Mono","SFMono-Regular",Consolas,ui-monospace,monospace;font-size:12.5px;color:rgba(255,255,255,0.7);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .review-row .rv.missing{color:rgba(255,255,255,0.3);font-style:italic;font-family:inherit}
  .review-row .rstat{font-family:"JetBrains Mono","SFMono-Regular",Consolas,ui-monospace,monospace;font-size:11px;letter-spacing:0.06em;text-transform:uppercase;text-align:right}
  .review-row .rstat.ok{color:#2ecc8f}
  .review-row .rstat.no{color:rgba(255,255,255,0.35)}
  .review-actions{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:18px 14px 8px;flex-wrap:wrap}
  .review-note{font-size:12.5px;color:rgba(255,255,255,0.42);max-width:46ch;line-height:1.5}
  .btn-continue{font-family:inherit;font-size:15px;font-weight:600;border:0;border-radius:11px;padding:13px 24px;cursor:pointer;color:#000;background:#fff;display:inline-flex;align-items:center;gap:9px;transition:transform .2s ease,box-shadow .2s ease,opacity .2s ease;white-space:nowrap}
  .btn-continue:hover{transform:translateY(-2px);box-shadow:0 14px 40px rgba(255,255,255,0.14)}
  .btn-continue[disabled]{opacity:0.35;cursor:not-allowed;transform:none;box-shadow:none}
  .toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(20px);background:#111;border:1px solid rgba(255,255,255,0.14);border-radius:11px;padding:12px 20px;font-size:13.5px;color:#fff;opacity:0;pointer-events:none;transition:opacity .25s ease,transform .25s ease;display:flex;align-items:center;gap:10px;z-index:200}
  .toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
  @media (max-width:980px){.cards{grid-template-columns:1fr}}
  @media (max-width:900px){.tabs{grid-template-columns:repeat(3,1fr)}}
  @media (max-width:720px){main{padding:42px 18px 72px}header.nav nav{padding:12px 18px}.tabs{grid-template-columns:repeat(2,1fr)}.review-row{grid-template-columns:1fr;gap:7px}.review-row .rstat{text-align:left}.brand .word{font-size:16px}.live-badge{font-size:10px}}
</style>
</head>
<body>
<div class="page">
  <div class="grid-bg"></div>
  <header class="nav">
    <nav>
      <a href="#" class="brand" aria-label="Consensus">
        <img src="${input.lightLogoUrl}" alt="">
        <span class="word">Consensus</span>
      </a>
      <span class="live-badge"><span class="d"></span>Node sign-up</span>
    </nav>
  </header>
  <main>
    <div class="mark-spin"></div>
    <div class="toprow">
      <div>
        <h1>Connect your payout wallets</h1>
        <p class="sub">Link <span class="em">MetaMask</span>, <span class="em">Phantom</span>, and <span class="em">Plug</span> so we know where to send your earnings. Connect each extension or paste its public payout address.</p>
      </div>
      <button type="button" class="steplink mono" id="manual-all">Paste addresses</button>
    </div>
    <div class="tabs" id="tabs">
      <button class="tab on" type="button" data-tab="all"><span class="tdot"></span>All wallets</button>
      <button class="tab" type="button" data-tab="evm" id="tab-evm"><span class="tdot"></span>MetaMask</button>
      <button class="tab" type="button" data-tab="sol" id="tab-sol"><span class="tdot"></span>Phantom</button>
      <button class="tab" type="button" data-tab="icp" id="tab-icp"><span class="tdot"></span>Plug</button>
      <button class="tab" type="button" data-tab="review"><span class="tdot"></span>Review</button>
    </div>
    <div class="cards" id="cards-pane">
      <div class="card" id="card-evm" data-card="evm">
        <div class="card-head"><span class="wicon evm">${metaMaskIcon()}</span><div><h3 class="card-title">MetaMask</h3><p class="card-desc">EVM payout address · Base, Ethereum</p></div></div>
        <div class="field"><span class="field-label">EVM address</span><div class="addr-box" id="addr-evm"><span class="atext">not connected</span></div></div>
        <div class="wallet-actions"><button class="btn-connect" type="button" id="btn-evm"><span class="spin"></span><span class="blabel">Connect MetaMask</span></button><button class="btn-manual" type="button" id="manual-evm" aria-expanded="false" aria-controls="entry-evm">Paste</button></div>
        <div class="manual-entry" id="entry-evm"><input class="manual-input" id="input-evm" type="text" inputmode="text" autocomplete="off" spellcheck="false" placeholder="0x..." aria-label="EVM payout address"><button class="manual-save" id="save-evm" type="button">Use address</button></div>
        <div class="status-line idle" id="status-evm"><span class="sdot"></span><span class="stext">Waiting to connect</span></div>
      </div>
      <div class="card" id="card-sol" data-card="sol">
        <div class="card-head"><span class="wicon sol">${phantomMark}</span><div><h3 class="card-title">Phantom</h3><p class="card-desc">Solana payout address · Devnet, Mainnet</p></div></div>
        <div class="field"><span class="field-label">Solana address</span><div class="addr-box" id="addr-sol"><span class="atext">not connected</span></div></div>
        <div class="wallet-actions"><button class="btn-connect" type="button" id="btn-sol"><span class="spin"></span><span class="blabel">Connect Phantom</span></button><button class="btn-manual" type="button" id="manual-sol" aria-expanded="false" aria-controls="entry-sol">Paste</button></div>
        <div class="manual-entry" id="entry-sol"><input class="manual-input" id="input-sol" type="text" inputmode="text" autocomplete="off" spellcheck="false" placeholder="Solana public key" aria-label="Solana payout address"><button class="manual-save" id="save-sol" type="button">Use address</button></div>
        <div class="status-line idle" id="status-sol"><span class="sdot"></span><span class="stext">Waiting to connect</span></div>
      </div>
      <div class="card" id="card-icp" data-card="icp">
        <div class="card-head"><span class="wicon icp">${plugMark}</span><div><h3 class="card-title">Plug</h3><p class="card-desc">ICP principal · node registry &amp; ckUSDC</p></div></div>
        <div class="field"><span class="field-label">ICP principal</span><div class="addr-box" id="addr-icp"><span class="atext">not connected</span></div></div>
        <div class="wallet-actions"><button class="btn-connect" type="button" id="btn-icp"><span class="spin"></span><span class="blabel">Connect Plug</span></button><button class="btn-manual" type="button" id="manual-icp" aria-expanded="false" aria-controls="entry-icp">Paste</button></div>
        <div class="manual-entry" id="entry-icp"><input class="manual-input" id="input-icp" type="text" inputmode="text" autocomplete="off" spellcheck="false" placeholder="aaaaa-aa" aria-label="ICP principal"><button class="manual-save" id="save-icp" type="button">Use address</button></div>
        <div class="status-line idle" id="status-icp"><span class="sdot"></span><span class="stext">Waiting to connect</span></div>
      </div>
    </div>
    <div class="review-pane" id="review-pane">
      <div class="review-row"><span class="rk"><span class="ricon" style="background:#f6851b33;border:1px solid #f6851b40">${metaMaskIcon()}</span>MetaMask</span><span class="rv missing" id="rv-evm">not connected</span><span class="rstat no" id="rs-evm">pending</span></div>
      <div class="review-row"><span class="rk"><span class="ricon" style="background:#ab9ff233;border:1px solid #ab9ff240">${phantomMark}</span>Phantom</span><span class="rv missing" id="rv-sol">not connected</span><span class="rstat no" id="rs-sol">pending</span></div>
      <div class="review-row"><span class="rk"><span class="ricon icp" style="background:#0271EB33;border:1px solid #0271EB40">${plugMark}</span>Plug</span><span class="rv missing" id="rv-icp">not connected</span><span class="rstat no" id="rs-icp">pending</span></div>
      <div class="review-actions"><span class="review-note" id="review-note">All three payout addresses must be provided before you can continue to node registration.</span><button class="btn-continue" type="button" id="btn-continue" disabled>Continue to node setup <span class="mono">-&gt;</span></button></div>
    </div>
  </main>
</div>
<div class="toast" id="toast"><span id="toast-text"></span></div>
<script>
(function () {
  const config = ${config};
  const $ = (id) => document.getElementById(id);
  const state = {
    evm: config.initialAddresses.evmAddress ? { address: config.initialAddresses.evmAddress, source: "saved" } : null,
    sol: config.initialAddresses.solanaAddress ? { address: config.initialAddresses.solanaAddress, source: "saved" } : null,
    icp: config.initialAddresses.icpAddress ? { principal: config.initialAddresses.icpAddress, source: "saved" } : null,
  };
  let autoReviewed = false;
  const announcedProviders = [];
  window.addEventListener("eip6963:announceProvider", (event) => {
    if (event.detail) announcedProviders.push(event.detail);
  });
  window.dispatchEvent(new Event("eip6963:requestProvider"));
  function short(addr, head = 6, tail = 4) {
    if (!addr) return "";
    if (addr.length <= head + tail + 3) return addr;
    return addr.slice(0, head) + "..." + addr.slice(-tail);
  }
  function toast(msg) {
    const t = $("toast");
    $("toast-text").textContent = msg;
    t.classList.add("show");
    clearTimeout(toast._h);
    toast._h = setTimeout(() => t.classList.remove("show"), 2600);
  }
  function setBusy(key, busy) {
    $("btn-" + key).classList.toggle("busy", busy);
  }
  function copyText(value, label) {
    navigator.clipboard?.writeText(value).then(() => toast("Copied " + label + " address")).catch(() => toast("Copy unavailable"));
  }
  function addressFor(key) {
    return key === "icp" ? state[key]?.principal : state[key]?.address;
  }
  function setAddress(key, value, source) {
    state[key] = key === "icp" ? { principal: value, source } : { address: value, source };
  }
  function manualValidationError(key, value) {
    if (key === "evm" && !/^0x[a-fA-F0-9]{40}$/.test(value)) return "EVM address must be 0x followed by 40 hex characters";
    if (key === "sol" && !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) return "Solana address must be a base58 public key";
    if (key === "icp" && !/^[a-z0-9]{1,5}(?:-[a-z0-9]{1,5})+$/.test(value)) return "ICP address must be a textual principal";
    return "";
  }
  function showManualEntry(key, focus = true) {
    const entry = $("entry-" + key);
    const button = $("manual-" + key);
    entry.classList.add("show");
    button.setAttribute("aria-expanded", "true");
    const input = $("input-" + key);
    input.value = addressFor(key) || input.value;
    if (focus) input.focus();
  }
  function toggleManualEntry(key) {
    const entry = $("entry-" + key);
    const open = !entry.classList.contains("show");
    entry.classList.toggle("show", open);
    $("manual-" + key).setAttribute("aria-expanded", String(open));
    if (open) {
      const input = $("input-" + key);
      input.value = addressFor(key) || input.value;
      input.focus();
    }
  }
  function saveManualAddress(key) {
    const value = $("input-" + key).value.trim();
    const error = manualValidationError(key, value);
    if (error) {
      const status = $("status-" + key);
      status.className = "status-line err";
      status.querySelector(".stext").textContent = error;
      toast(error);
      return;
    }
    setAddress(key, value, "manual");
    $("entry-" + key).classList.remove("show");
    $("manual-" + key).setAttribute("aria-expanded", "false");
    renderAll();
    toast("Public address added");
  }
  function renderWallet(key, label) {
    const data = state[key];
    const display = addressFor(key);
    const addrBox = $("addr-" + key);
    const btn = $("btn-" + key);
    const status = $("status-" + key);
    const card = $("card-" + key);
    const tab = $("tab-" + key);
    if (display) {
      addrBox.classList.add("filled");
      addrBox.innerHTML = '<span class="atext"></span><button class="copy" type="button" title="Copy">⧉</button>';
      addrBox.querySelector(".atext").textContent = display;
      addrBox.querySelector(".atext").title = display;
      addrBox.querySelector(".copy").addEventListener("click", () => copyText(display, label));
      btn.classList.toggle("connected", data.source === "wallet");
      btn.querySelector(".blabel").textContent = data.source === "wallet" ? "Connected · reconnect" : "Connect " + label;
      status.className = "status-line ok";
      status.querySelector(".stext").textContent = data.source === "wallet" ? "Connected " + short(display) : "Address added " + short(display);
      card.classList.add("connected");
      if (tab) tab.classList.add("done");
    } else {
      addrBox.classList.remove("filled");
      addrBox.innerHTML = '<span class="atext">not connected</span>';
      btn.classList.remove("connected");
      btn.querySelector(".blabel").textContent = "Connect " + label;
      status.className = "status-line idle";
      status.querySelector(".stext").textContent = "Waiting to connect";
      card.classList.remove("connected");
      if (tab) tab.classList.remove("done");
    }
  }
  function renderReview() {
    const rows = [["evm", state.evm?.address], ["sol", state.sol?.address], ["icp", state.icp?.principal]];
    rows.forEach(([key, val]) => {
      const rv = $("rv-" + key);
      const rs = $("rs-" + key);
      if (val) {
        rv.textContent = val;
        rv.classList.remove("missing");
        rs.textContent = state[key]?.source === "wallet" ? "connected" : "provided";
        rs.className = "rstat ok";
      } else {
        rv.textContent = "not connected";
        rv.classList.add("missing");
        rs.textContent = "pending";
        rs.className = "rstat no";
      }
    });
    $("btn-continue").disabled = !allProvided();
  }
  function renderAll() {
    renderWallet("evm", "MetaMask");
    renderWallet("sol", "Phantom");
    renderWallet("icp", "Plug");
    renderReview();
    maybeAutoReview();
  }
  function allProvided() {
    return Boolean(state.evm && state.sol && state.icp);
  }
  function isMetaMaskAnnouncement(entry) {
    const rdns = String(entry?.info?.rdns || "").toLowerCase();
    const name = String(entry?.info?.name || "").toLowerCase();
    return entry?.provider && (rdns === "io.metamask" || name === "metamask");
  }
  function isMetaMaskProvider(provider) {
    return Boolean(provider?.isMetaMask && !provider?.isPhantom && !provider?.isCoinbaseWallet && !provider?.isBraveWallet && !provider?.isRabby && !provider?.isFrame && !provider?.isTrust && !provider?.isPlug);
  }
  async function getMetaMaskProvider() {
    window.dispatchEvent(new Event("eip6963:requestProvider"));
    await new Promise((resolve) => setTimeout(resolve, 180));
    const announced = announcedProviders.find(isMetaMaskAnnouncement);
    if (announced) return announced.provider;
    const injected = window.ethereum?.providers?.length ? window.ethereum.providers : [window.ethereum].filter(Boolean);
    return injected.find(isMetaMaskProvider) || null;
  }
  function walletError(error, fallback) {
    if (error?.code === 4001) return "Connection rejected";
    return error?.message || fallback;
  }
  async function connectEvm() {
    const provider = await getMetaMaskProvider();
    if (!provider?.request) {
      toast("MetaMask not detected - paste its public address instead");
      $("status-evm").className = "status-line err";
      $("status-evm").querySelector(".stext").textContent = "MetaMask not found - paste the public address";
      showManualEntry("evm");
      return;
    }
    setBusy("evm", true);
    try {
      const accounts = await provider.request({ method: "eth_requestAccounts" });
      if (accounts && accounts[0]) {
        state.evm = { address: accounts[0], source: "wallet" };
        renderAll();
        toast("MetaMask connected");
      }
    } catch (error) {
      toast(walletError(error, "Could not connect MetaMask"));
    } finally {
      setBusy("evm", false);
    }
  }
  async function connectSol() {
    const provider = window.phantom?.solana || (window.solana?.isPhantom ? window.solana : null);
    if (!provider) {
      toast("Phantom not detected - paste its public address instead");
      $("status-sol").className = "status-line err";
      $("status-sol").querySelector(".stext").textContent = "Phantom not found - paste the public address";
      showManualEntry("sol");
      return;
    }
    setBusy("sol", true);
    try {
      const response = await provider.connect();
      const address = response?.publicKey?.toString?.() || provider.publicKey?.toString?.();
      if (address) {
        state.sol = { address, source: "wallet" };
        renderAll();
        toast("Phantom connected");
      }
    } catch (error) {
      toast(walletError(error, "Could not connect Phantom"));
    } finally {
      setBusy("sol", false);
    }
  }
  async function connectIcp() {
    const plug = window.ic?.plug;
    if (!plug?.requestConnect) {
      toast("Plug not detected - paste its public address instead");
      $("status-icp").className = "status-line err";
      $("status-icp").querySelector(".stext").textContent = "Plug not found - paste the public principal";
      showManualEntry("icp");
      return;
    }
    setBusy("icp", true);
    try {
      const connected = await plug.requestConnect({ whitelist: [], host: "https://icp0.io" });
      if (connected === false) throw new Error("Plug did not approve the connection.");
      const agentPrincipal = await plug.agent?.getPrincipal?.();
      const principal = agentPrincipal?.toText?.() || agentPrincipal?.toString?.() || plug.principalId;
      if (!principal) throw new Error("Plug did not return a principal.");
      state.icp = { principal, source: "wallet" };
      renderAll();
      toast("Plug connected");
    } catch (error) {
      toast(walletError(error, "Could not connect Plug"));
    } finally {
      setBusy("icp", false);
    }
  }
  async function submitAddresses() {
    if ($("btn-continue").disabled) return;
    $("btn-continue").disabled = true;
    $("btn-continue").textContent = "Saving wallets...";
    try {
      const response = await fetch(config.submitUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          evmAddress: state.evm?.address || "",
          solanaAddress: state.sol?.address || "",
          icpAddress: state.icp?.principal || "",
        }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Address submission failed.");
      $("review-note").textContent = "Wallets saved. Return to the terminal if this tab does not close automatically.";
      $("btn-continue").textContent = "Wallets saved";
      toast("Wallets saved - closing tab...");
      setTimeout(() => {
        window.open("", "_self");
        window.close();
        document.body.innerHTML = '<div style="min-height:100vh;display:grid;place-items:center;background:#000;color:#fff;font:16px system-ui">Wallets saved. Return to the terminal.</div>';
      }, 2400);
    } catch (error) {
      $("btn-continue").disabled = false;
      $("btn-continue").innerHTML = 'Continue to node setup <span class="mono">-&gt;</span>';
      toast(walletError(error, "Address submission failed."));
    }
  }
  $("btn-evm").addEventListener("click", connectEvm);
  $("btn-sol").addEventListener("click", connectSol);
  $("btn-icp").addEventListener("click", connectIcp);
  ["evm", "sol", "icp"].forEach((key) => {
    $("manual-" + key).addEventListener("click", () => toggleManualEntry(key));
    $("save-" + key).addEventListener("click", () => saveManualAddress(key));
    $("input-" + key).addEventListener("keydown", (event) => {
      if (event.key === "Enter") saveManualAddress(key);
    });
  });
  $("btn-continue").addEventListener("click", submitAddresses);
  $("manual-all").addEventListener("click", () => {
    showTab("all");
    ["evm", "sol", "icp"].forEach((key) => showManualEntry(key, false));
    const firstMissing = ["evm", "sol", "icp"].find((key) => !addressFor(key));
    $("input-" + (firstMissing || "evm")).focus();
  });
  const cardsPane = $("cards-pane");
  const reviewPane = $("review-pane");
  function showTab(which) {
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("on", x.dataset.tab === which));
    if (which === "review") {
      cardsPane.style.display = "none";
      reviewPane.classList.add("show");
      return;
    }
    reviewPane.classList.remove("show");
    cardsPane.style.display = "grid";
    document.querySelectorAll("[data-card]").forEach((card) => {
      card.style.display = (which === "all" || which === card.dataset.card) ? "flex" : "none";
    });
  }
  function maybeAutoReview() {
    if (!allProvided() || autoReviewed) return;
    autoReviewed = true;
    setTimeout(() => showTab("review"), 250);
  }
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => showTab(tab.dataset.tab));
  });
  function activateStartPage() {
    const pageMap = { overview: "all", metamask: "evm", phantom: "sol", plug: "icp", review: "review" };
    showTab(pageMap[config.startPage] || "all");
  }
  renderAll();
  activateStartPage();
})();
</script>
</body>
</html>`;
}

function metaMaskIcon(): string {
  return `<svg viewBox="0 0 64 64" aria-hidden="true" focusable="false"><path fill="#f6851b" d="M58.5 6 36.2 22.5l4.1-9.7L58.5 6Z"/><path fill="#e2761b" d="M5.5 6 27.6 22.7l-3.9-9.9L5.5 6Zm45 38.8-5.9 9.1 12.7 3.5 3.6-12.4-10.4-.2Zm-47.3.2 3.5 12.4 12.7-3.5-5.9-9.1-10.3.2Z"/><path fill="#e4761b" d="m18.7 29.4-3.5 5.3 12.6.6-.4-13.6-8.7 7.7Zm26.6 0-8.8-7.9-.3 13.8 12.6-.6-3.5-5.3Zm-25.9 24.5 7.6-3.7-6.6-5.1-1 8.8Zm17.6-3.7 7.7 3.7-1.1-8.8-6.6 5.1Z"/><path fill="#d7c1b3" d="m44.7 53.9-7.7-3.7.6 5-.1 2.1 7.2-3.4Zm-25.3 0 7.2 3.4-.1-2.1.5-5-7.6 3.7Z"/><path fill="#233447" d="m26.7 41.8-6.4-1.9 4.5-2.1 1.9 4Zm10.6 0 1.9-4 4.5 2.1-6.4 1.9Z"/><path fill="#cd6116" d="m19.4 53.9 1.1-9.1-7-.2 5.9 9.3Zm24.1-9.1 1.2 9.1 5.9-9.3-7.1.2Zm5.3-10.1-12.6.6 1.2 6.5 1.9-4 4.5 2.1 5-5.2Zm-28.6 5.2 4.5-2.1 1.9 4 1.2-6.5-12.6-.6 5 5.2Z"/><path fill="#e4751f" d="m15.2 34.7 5.3 10.1-.2-4.9-5.1-5.2Zm28.5 5.2-.2 4.9 5.3-10.1-5.1 5.2Zm-15.9-4.6-1.2 6.5 1.5 7.8.3-10.3-.6-4Zm8.4 0-.6 4 .3 10.3 1.5-7.8-1.2-6.5Z"/><path fill="#f6851b" d="m37.4 41.8-1.5 7.8 1.1.6 6.6-5.1.2-5.2-6.4 1.9Zm-17.2-1.9.2 5.2 6.6 5.1 1.1-.6-1.5-7.8-6.4-1.9Z"/><path fill="#c0ad9e" d="m37.5 57.3.1-2.1-.5-.4H26.9l-.4.4.1 2.1-7.2-3.4 2.5 2.1 5 3.5h10.2l5-3.5 2.6-2.1-7.2 3.4Z"/><path fill="#161616" d="m37 50.2-1.1-.6h-7.8l-1.1.6-.5 5 .4-.4h10.2l.5.4-.6-5Z"/><path fill="#763d16" d="m59.5 23.6 1.9-9.3-2.9-8.3L37 21.9l8.3 7.5 11.7 3.4 2.6-3-1.1-.8 1.8-1.7-1.4-1.1 1.8-1.4-1.2-1.2ZM2.6 14.3l1.9 9.3-1.2 1.2 1.8 1.4-1.4 1.1 1.8 1.7-1.1.8 2.6 3 11.7-3.4 8.3-7.5L5.5 6l-2.9 8.3Z"/><path fill="#f6851b" d="m57 32.8-11.7-3.4 3.5 5.3-5.3 10.1 7 .1h10.4L57 32.8ZM18.7 29.4 7 32.8 3.1 44.9h10.4l7-.1-5.3-10.1 3.5-5.3Zm17.5 5.9.8-13.4 3.5-9.1h-17l3.5 9.1.8 13.4.3 4.2v10.1h7.8V39.5l.3-4.2Z"/></svg>`;
}

function safeScriptJson(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

if (import.meta.main) {
  const session = await startWalletAddressServer();
  console.log("Wallet address page:");
  console.log(session.url);
  if (process.env.CONSENSUS_WALLET_CAPTURE_OPEN?.trim() !== "0") {
    openWalletAddressPage(session.url).catch((error) => {
      console.warn(`Could not open browser automatically: ${error instanceof Error ? error.message : String(error)}`);
    });
  }

  try {
    const addresses = await session.done;
    console.log("Wallet addresses received:");
    console.log(JSON.stringify(addresses, null, 2));
  } finally {
    await session.stop().catch(() => {});
  }
}
