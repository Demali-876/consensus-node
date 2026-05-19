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

module.exports = {
  apps: [
    {
      name: appName,
      script: path.join(currentDir, "scripts", "run-control.sh"),
      interpreter: "/bin/bash",
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
