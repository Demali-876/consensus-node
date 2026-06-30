const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const installDir = process.env.CONSENSUS_NODE_INSTALL_DIR ||
  path.join(os.homedir(), ".consensus", "node-runtime");
const stateDir = process.env.CONSENSUS_STATE_DIR ||
  path.join(os.homedir(), ".consensus", "node");
const serverUrl = process.env.CONSENSUS_SERVER_URL ||
  "https://consensus.canister.software";
const appName = process.env.CONSENSUS_PM2_NAME || "consensus-node-control";
const currentDir = path.join(installDir, "current");

fs.mkdirSync(stateDir, { recursive: true });

// run-node.sh needs bash >= 4.3 (`wait -n`). PM2's `interpreter` overrides the script
// shebang, so pin a sufficiently new bash explicitly — preferring Homebrew bash on
// macOS, where /bin/bash is 3.2 (so the documented Homebrew workaround actually takes
// effect under PM2). Falls back to /bin/bash, where run-node.sh prints a clear error,
// so evaluating this config never throws.
function resolveBash() {
  const { execSync } = require("node:child_process");
  for (const bash of ["/opt/homebrew/bin/bash", "/usr/local/bin/bash", "/usr/bin/bash", "/bin/bash"]) {
    try {
      if (!fs.existsSync(bash)) continue;
      const out = execSync(`${bash} --version`, { stdio: ["ignore", "pipe", "ignore"] }).toString();
      const m = out.match(/version (\d+)\.(\d+)/);
      if (m && (Number(m[1]) > 4 || (Number(m[1]) === 4 && Number(m[2]) >= 3))) return bash;
    } catch {
      /* try next candidate */
    }
  }
  return "/bin/bash";
}

const bashInterpreter = resolveBash();

module.exports = {
  apps: [
    {
      name: appName,
      // run-node.sh runs the outbound control tunnel (which carries the data
      // plane via the orchestrator gateway) AND a loopback-only runtime server as
      // one unit. (run-control.sh, control-only, is kept for reference.)
      script: path.join(currentDir, "scripts", "run-node.sh"),
      interpreter: bashInterpreter,
      cwd: currentDir,
      instances: 1,
      exec_mode: "fork",
      autorestart: true,
      watch: false,
      min_uptime: "10s",
      max_restarts: 1000,
      restart_delay: 5000,
      kill_timeout: 30000,
      time: true,
      merge_logs: true,
      out_file: path.join(stateDir, "pm2.out.log"),
      error_file: path.join(stateDir, "pm2.err.log"),
      env: {
        CONSENSUS_SERVER_URL: serverUrl,
        CONSENSUS_STATE_DIR: stateDir,
        CONSENSUS_NODE_INSTALL_DIR: installDir,
        CONSENSUS_NODE_RELEASE_RETENTION: process.env.CONSENSUS_NODE_RELEASE_RETENTION || "3",
        CONSENSUS_NODE_UPDATE_COMMAND: process.env.CONSENSUS_NODE_UPDATE_COMMAND ||
          path.join(currentDir, "scripts", "install-release.sh"),
      },
    },
  ],
};
