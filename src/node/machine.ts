import { randomUUID } from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { stateDir } from "./state";

export interface MachineRegistry {
  machine_id: string;
  created_at: string;
  updated_at: string;
  state_dir?: string;
  install_dir?: string;
  node_id?: string;
  registered_at?: string;
}

export function machineRegistryDir(): string {
  return process.env.CONSENSUS_MACHINE_REGISTRY_DIR?.trim() || path.join(os.homedir(), ".consensus");
}

export function machineRegistryPath(): string {
  return path.join(machineRegistryDir(), "machine.json");
}

export async function loadOrCreateMachineRegistry(): Promise<MachineRegistry> {
  const existing = await loadMachineRegistry();
  if (existing) return existing;

  const now = new Date().toISOString();
  const registry: MachineRegistry = {
    machine_id: randomUUID(),
    created_at: now,
    updated_at: now,
  };
  await saveMachineRegistry(registry);
  return registry;
}

export async function assertMachineCanRegister(options: { existingNodeId?: string; stateDir?: string } = {}): Promise<MachineRegistry> {
  const registry = await loadOrCreateMachineRegistry();
  const currentStateDir = normalizeDir(options.stateDir ?? stateDir());

  if (registry.node_id && registry.state_dir && normalizeDir(registry.state_dir) !== currentStateDir) {
    throw new Error(
      `This machine is already registered as ${registry.node_id} using state ${registry.state_dir}. ` +
        "Consensus allows one node per machine; use that existing node state instead of registering another.",
    );
  }

  if (registry.node_id && !registry.state_dir && !options.existingNodeId) {
    throw new Error(
      `This machine is already registered as ${registry.node_id}. ` +
        "Consensus allows one node per machine; use the existing node state instead of registering another.",
    );
  }

  if (registry.node_id && options.existingNodeId && registry.node_id !== options.existingNodeId) {
    throw new Error(
      `This machine is already registered as ${registry.node_id}; current state has ${options.existingNodeId}. ` +
        "Consensus allows one node per machine.",
    );
  }

  return registry;
}

export async function claimMachineNode(input: { nodeId: string; installDir?: string; stateDir?: string }): Promise<MachineRegistry> {
  const registry = await assertMachineCanRegister({ existingNodeId: input.nodeId, stateDir: input.stateDir });
  const now = new Date().toISOString();
  const next: MachineRegistry = {
    ...registry,
    node_id: input.nodeId,
    state_dir: normalizeDir(input.stateDir ?? stateDir()),
    install_dir: input.installDir ? normalizeDir(input.installDir) : registry.install_dir,
    registered_at: registry.registered_at ?? now,
    updated_at: now,
  };
  await saveMachineRegistry(next);
  return next;
}

async function loadMachineRegistry(): Promise<MachineRegistry | null> {
  try {
    const parsed = JSON.parse(await fs.readFile(machineRegistryPath(), "utf8")) as Partial<MachineRegistry>;
    if (!parsed.machine_id || typeof parsed.machine_id !== "string") {
      throw new Error(`Machine registry is missing machine_id at ${machineRegistryPath()}`);
    }
    return {
      machine_id: parsed.machine_id,
      created_at: typeof parsed.created_at === "string" ? parsed.created_at : new Date().toISOString(),
      updated_at: typeof parsed.updated_at === "string" ? parsed.updated_at : new Date().toISOString(),
      state_dir: typeof parsed.state_dir === "string" ? parsed.state_dir : undefined,
      install_dir: typeof parsed.install_dir === "string" ? parsed.install_dir : undefined,
      node_id: typeof parsed.node_id === "string" ? parsed.node_id : undefined,
      registered_at: typeof parsed.registered_at === "string" ? parsed.registered_at : undefined,
    };
  } catch (error) {
    if (isNotFound(error)) return null;
    throw error;
  }
}

async function saveMachineRegistry(registry: MachineRegistry): Promise<void> {
  const file = machineRegistryPath();
  await fs.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(registry, null, 2), { encoding: "utf8", mode: 0o600 });
  await fs.rename(tmp, file);
  await fs.chmod(file, 0o600).catch(() => {});
}

function normalizeDir(value: string): string {
  return path.resolve(value);
}

function isNotFound(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && (error as { code?: unknown }).code === "ENOENT");
}
