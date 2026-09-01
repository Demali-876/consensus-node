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

// PM2's `interpreter` overrides the script shebang, so bun has to be named
// explicitly. Resolve it to an ABSOLUTE path: this config is also evaluated when PM2
// itself is started by a boot-time daemon (launchd/systemd), whose PATH does not
// include ~/.bun/bin, so a bare "bun" would not resolve there. Falls back to the bare
// name — where PM2 reports a clear interpreter error — so evaluating this never throws.
function resolveBun() {
  const candidates = [
    process.env.CONSENSUS_BUN_PATH,
    path.join(os.homedir(), ".bun", "bin", "bun"),
    "/opt/homebrew/bin/bun",
    "/usr/local/bin/bun",
    "/usr/bin/bun",
  ];
  for (const candidate of candidates) {
    try {
      if (candidate && fs.existsSync(candidate)) return candidate;
    } catch {
      /* try next candidate */
    }
  }
  return "bun";
}

const bunInterpreter = resolveBun();

module.exports = {
  apps: [
    {
      name: appName,
      // supervise.ts runs the outbound control tunnel (which carries the data
      // plane via the orchestrator gateway) AND a loopback-only runtime server as
      // one unit. (run-control.sh, control-only, is kept for reference.)
      script: path.join(currentDir, "src", "supervise.ts"),
      interpreter: bunInterpreter,
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
