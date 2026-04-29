import crypto from "node:crypto";
import os from "node:os";
import { execFileSync } from "node:child_process";
import packageJson from "../../package.json";
import { canonicalJson } from "../crypto/canonical-json";
import { NODE_CAPABILITIES } from "../runtime/capabilities";
import type { ReleaseManifest } from "../types";

interface NodePackageJson {
  version?: string;
  consensus_node?: {
    commit?: string;
    platform?: string;
  };
}

const packageMetadata = packageJson as NodePackageJson;

export const REQUIRED_ROUTES = [
  "GET /health",
  "GET /node/version",
  "GET /node/manifest",
  "GET /node/integrity",
  "GET /node/capabilities",
  "POST /benchmark/fetch",
  "POST /benchmark/cpu",
  "GET /benchmark/system",
  "POST /proxy"
] as const;

export function platform(): string {
  if (process.env.CONSENSUS_NODE_PLATFORM) return process.env.CONSENSUS_NODE_PLATFORM;
  if (packageMetadata.consensus_node?.platform) return packageMetadata.consensus_node.platform;
  return `${os.platform()}-${os.arch()}`;
}

export function routesHash(): string {
  return `sha256:${crypto.createHash("sha256").update(canonicalJson([...REQUIRED_ROUTES])).digest("hex")}`;
}

export function releaseManifest(): ReleaseManifest {
  return {
    product: "consensus-node",
    version: process.env.CONSENSUS_NODE_VERSION || packageMetadata.version || "0.0.0",
    artifact: "npm-tarball",
    platform: platform(),
    commit: process.env.CONSENSUS_NODE_COMMIT || packageMetadata.consensus_node?.commit || gitCommit() || "unknown",
    download_url: process.env.CONSENSUS_NODE_DOWNLOAD_URL,
    tarball_sha256: process.env.CONSENSUS_NODE_TARBALL_SHA256,
    routes_hash: routesHash(),
    capabilities: NODE_CAPABILITIES,
    signing_key_id: process.env.CONSENSUS_RELEASE_SIGNING_KEY_ID,
    signature: process.env.CONSENSUS_RELEASE_SIGNATURE
  };
}

function gitCommit(): string | null {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: new URL("../..", import.meta.url),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim() || null;
  } catch {
    return null;
  }
}
