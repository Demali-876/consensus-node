// Whether this machine is configured to bring the node back after a reboot with no
// login.
//
// This exists for nodes that were onboarded BEFORE the boot unit did — they will
// never see the setup wizard again, so the runtime itself has to tell them. The
// supervisor logs it at startup and /health reports it, which also lets an operator
// (or the orchestrator) see which nodes would not survive an unattended reboot.
//
// Detection is by the presence of the boot unit the installers write. That is a
// weaker signal than observing an actual boot — it says "configured to start at
// boot", not "observed to have started at boot". Proving the latter needs
// scripts/node-service.sh verify on a machine where nobody has logged in, which is
// a question a running process cannot answer about itself.

import fs from "node:fs";

const LAUNCHD_UNIT = "/Library/LaunchDaemons/com.consensus.node.plist";
const SYSTEMD_UNITS = [
  "/etc/systemd/system/consensus-node.service",
  "/lib/systemd/system/consensus-node.service",
  "/usr/lib/systemd/system/consensus-node.service",
];

export interface HeadlessBootStatus {
  configured: boolean;
  mechanism: "launchd" | "systemd" | "unknown";
  unit: string | null;
  detail: string;
}

function exists(file: string): boolean {
  try {
    return fs.existsSync(file);
  } catch {
    return false;
  }
}

export function headlessBootStatus(): HeadlessBootStatus {
  if (process.platform === "darwin") {
    if (exists(LAUNCHD_UNIT)) {
      return {
        configured: true,
        mechanism: "launchd",
        unit: LAUNCHD_UNIT,
        detail: "LaunchDaemon installed; starts at boot without a login.",
      };
    }
    return {
      configured: false,
      mechanism: "launchd",
      unit: null,
      // Named explicitly because `pm2 startup` is the thing operators reach for, and
      // on macOS it writes a LaunchAgent, which loads only at user login.
      detail:
        "No LaunchDaemon. This node will NOT come back after a reboot until someone logs in. " +
        "Run: sudo scripts/install-launchd.sh (pm2 startup does NOT work here — it writes a login-gated LaunchAgent).",
    };
  }

  if (process.platform === "linux") {
    const unit = SYSTEMD_UNITS.find(exists);
    if (unit) {
      return { configured: true, mechanism: "systemd", unit, detail: "systemd unit installed." };
    }
    return {
      configured: false,
      mechanism: "systemd",
      unit: null,
      detail:
        "No systemd unit. This node will NOT restart after a reboot. " +
        "Install systemd/consensus-node.service and enable it.",
    };
  }

  return {
    configured: false,
    mechanism: "unknown",
    unit: null,
    detail: `Unsupported platform for headless boot: ${process.platform}`,
  };
}
