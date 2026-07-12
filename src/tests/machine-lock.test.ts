import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { assertMachineCanRegister, claimMachineNode, loadOrCreateMachineRegistry } from "../node/machine";

const root = await fs.mkdtemp(path.join(os.tmpdir(), "consensus-machine-lock-"));
const stateOne = path.join(root, "state-one");
const stateTwo = path.join(root, "state-two");

process.env.CONSENSUS_MACHINE_REGISTRY_DIR = path.join(root, "registry");
process.env.CONSENSUS_STATE_DIR = stateOne;

try {
  const registry = await loadOrCreateMachineRegistry();
  assert.equal(typeof registry.machine_id, "string");
  assert.equal(registry.machine_id.length > 10, true);

  await assertMachineCanRegister();
  const claimed = await claimMachineNode({ nodeId: "node-one", installDir: path.join(root, "runtime-one") });
  assert.equal(claimed.node_id, "node-one");
  assert.equal(claimed.state_dir, stateOne);

  await assertMachineCanRegister({ existingNodeId: "node-one", stateDir: stateOne });
  await assert.rejects(
    () => assertMachineCanRegister({ stateDir: stateTwo }),
    /one node per machine/,
  );
  await assert.rejects(
    () => claimMachineNode({ nodeId: "node-two", stateDir: stateOne }),
    /already registered as node-one/,
  );
} finally {
  delete process.env.CONSENSUS_MACHINE_REGISTRY_DIR;
  delete process.env.CONSENSUS_STATE_DIR;
  await fs.rm(root, { recursive: true, force: true });
}

console.log("machine lock ok");
