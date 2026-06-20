export type NodeCapability =
  | "forward_proxy"
  | "reverse_proxy"
  | "websockets"
  | "tunnels"
  | "ip_leasing";

/** Orchestrator Ed25519 verification key (OKP public JWK), pinned at join.
 *  Mirrors `publicJwk()` in consensus/server/features/tickets/keys.ts. */
export interface OrchestratorPublicJwk {
  kty: string;
  crv: string;
  x: string;
  use?: string;
  alg?: string;
  kid?: string;
}

export interface NodeConfig {
  node_id?: string;
  domain?: string;
  region?: string;
  ipv4?: string | null;
  ipv6?: string | null;
  port: number;
  registered_at?: string;
  commissioned_at?: string;
  benchmark_score?: number;
  /** Pinned at registration; used to verify routing tickets. Null/absent until
   *  a join response carries it (e.g. older server, or FREE_MODE dev). */
  orchestrator_pubkey?: OrchestratorPublicJwk | null;
}

export interface ReleaseManifest {
  product: "consensus-node";
  version: string;
  artifact: "npm-tarball";
  platform: string;
  commit: string;
  download_url?: string;
  tarball_sha256?: string;
  routes_hash: string;
  capabilities: NodeCapability[];
  signing_key_id?: string;
  signature?: string;
}

export interface IntegrityPayload {
  product: "consensus-node";
  version: string;
  runtime: "bun";
  platform: string;
  node_public_key_pem: string;
  manifest: ReleaseManifest;
  timestamp: number;
  nonce: string;
  signature: string;
}
