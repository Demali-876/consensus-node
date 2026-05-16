import os from "node:os";

export interface SystemResult {
  platform: string;
  arch: string;
  cpus: number;
  total_memory_bytes: number;
  free_memory_bytes: number;
  uptime_seconds: number;
  bun_version: string;
}

export function runSystem(): SystemResult {
  return {
    platform: os.platform(),
    arch: os.arch(),
    cpus: os.cpus().length,
    total_memory_bytes: os.totalmem(),
    free_memory_bytes: os.freemem(),
    uptime_seconds: os.uptime(),
    bun_version: Bun.version,
  };
}
