(function(){
  const config = window.__CONSENSUS_SETUP_CONFIG__;
  const byId = (id) => document.getElementById(id);
  const installDir = byId("install-dir");
  const selectInstallDir = byId("select-install-dir");
  const resetInstallDir = byId("reset-install-dir");
  const continueButton = byId("continue");
  const continueLabel = byId("continue-label");
  const helper = byId("helper");
  const installBunButton = byId("install-bun");
  const installPm2Button = byId("install-pm2");
  const railCurrent = byId("rail-current");
  const progress = config.progress;

  let toolsReady = false;

  byId("state-dir").textContent = "state - " + progress.stateDir;

  function installDirValid() {
    const value = installDir.value.trim();
    return value.startsWith("/");
  }

  function syncPathState() {
    const valid = installDirValid();
    installDir.classList.toggle("invalid", !valid);
    byId("install-dir-error").classList.toggle("show", !valid);
    resetInstallDir.disabled = installDir.value === installDir.dataset.default;
    syncContinue();
  }

  function syncContinue() {
    continueButton.disabled = !toolsReady || !installDirValid();
  }

  function setRow(rowId, state, status, detail) {
    const row = byId(rowId);
    const icon = row.querySelector(".env-icon");
    const statusEl = row.querySelector(".env-status");
    const detailEl = row.querySelector(".et-sub");
    const glyph = { ok: "✓", warn: "!", busy: "-", pending: "-", err: "!" }[state] || "-";

    row.classList.remove("ok", "warn", "err", "busy", "pending");
    row.classList.add(state);
    icon.className = "env-icon " + state;
    icon.querySelector(".estatic").textContent = glyph;
    statusEl.hidden = false;
    statusEl.className = "env-status mono " + (state === "busy" ? "pending" : state);
    statusEl.textContent = status;
    detailEl.textContent = detail;
  }

  function setInstallAction(rowId, button, active) {
    const statusEl = byId(rowId).querySelector(".env-status");
    statusEl.hidden = active;
    button.hidden = !active;
  }

  function setRowWarning(id, message) {
    const warning = byId(id);
    warning.textContent = message || "";
    warning.classList.toggle("show", Boolean(message));
  }

  function showBlocker(message, options = {}) {
    setInstallAction("env-bun", installBunButton, Boolean(options.canInstallBun));
    setInstallAction("env-pm2", installPm2Button, Boolean(options.canInstallPm2));
    setRowWarning("bun-warning", options.canInstallBun ? options.bunMessage || message : "");
    setRowWarning("pm2-warning", options.canInstallPm2 ? options.pm2Message || message : "");
  }

  function clearBlocker() {
    setInstallAction("env-bun", installBunButton, false);
    setInstallAction("env-pm2", installPm2Button, false);
    setRowWarning("bun-warning", "");
    setRowWarning("pm2-warning", "");
  }

  function applyEnvironment(body) {
    const bun = body.bun || {};
    const pm2 = body.pm2 || {};
    setRow("env-bun", bun.available ? "ok" : "err", bun.available ? "Detected" : "Missing", bun.detail || "bun --version");
    setRow("env-pm2", pm2.available ? "ok" : "err", pm2.available ? "Detected" : "Missing", pm2.detail || "pm2 --version");

    toolsReady = Boolean(bun.available && pm2.available);
    if (toolsReady) {
      clearBlocker();
      helper.textContent = "Runtime tools are ready. Confirm the install directory to continue.";
      railCurrent.textContent = "environment ready";
    } else {
      const missingBun = !bun.available;
      const missingPm2 = !pm2.available;
      helper.textContent = missingBun && missingPm2
        ? "Bun and PM2 can be installed by the local setup process."
        : missingBun
          ? "Bun can be installed by the local setup process."
          : "PM2 can be installed by the local setup process.";
      railCurrent.textContent = missingBun && missingPm2
        ? "blocked - tools missing"
        : missingBun
          ? "blocked - bun missing"
          : "blocked - pm2 missing";
      showBlocker("Required before continuing.", {
        canInstallBun: missingBun,
        canInstallPm2: missingPm2,
        bunMessage: "Bun is required to install and run Consensus.",
        pm2Message: "PM2 is required to supervise the node process.",
      });
    }
    syncContinue();
  }

  async function checkEnvironment() {
    toolsReady = false;
    syncContinue();
    clearBlocker();
    helper.textContent = "Checking Bun and PM2 on this machine...";
    railCurrent.textContent = "checking bun and pm2";
    setRow("env-bun", "busy", "Checking", "bun --version");
    setRow("env-pm2", "pending", "Queued", "pm2 --version");

    try {
      const response = await fetch(config.environmentUrl, { cache: "no-store" });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || "Environment check failed");
      applyEnvironment(body);
    } catch (error) {
      setRow("env-bun", "err", "Failed", "environment check failed");
      setRow("env-pm2", "err", "Failed", "environment check failed");
      helper.textContent = error.message || "Environment check failed";
      railCurrent.textContent = "environment check failed";
      showBlocker("The local setup server could not complete the environment check. Retry the check.");
    }

    syncContinue();
  }

  async function installPm2() {
    await installTool({
      button: installPm2Button,
      url: config.pm2InstallUrl,
      rowId: "env-pm2",
      label: "PM2",
      runningText: "Installing PM2 with scripts/ensure-pm2.sh...",
      railText: "installing pm2",
      detail: "scripts/ensure-pm2.sh --yes",
      failureText: "PM2 installation failed. You can retry, or run scripts/ensure-pm2.sh in the terminal.",
      failureOptions: { canInstallPm2: true },
    });
  }

  async function installBun() {
    await installTool({
      button: installBunButton,
      url: config.bunInstallUrl,
      rowId: "env-bun",
      label: "Bun",
      runningText: "Installing Bun with scripts/ensure-bun.sh...",
      railText: "installing bun",
      detail: "scripts/ensure-bun.sh --yes",
      failureText: "Bun installation failed. You can retry, or run scripts/ensure-bun.sh in the terminal.",
      failureOptions: { canInstallBun: true },
    });
  }

  async function installTool(input) {
    input.button.disabled = true;
    input.button.textContent = "Installing";
    helper.textContent = input.runningText;
    railCurrent.textContent = input.railText;
    setRow(input.rowId, "busy", "Installing", input.detail);
    setInstallAction(input.rowId, input.button, true);

    try {
      const response = await fetch(input.url, { method: "POST" });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || input.label + " installation failed");
      applyEnvironment(body.environment || {});
    } catch (error) {
      setRow(input.rowId, "err", "Failed", input.label.toLowerCase() + " install failed");
      helper.textContent = error.message || input.label + " installation failed";
      railCurrent.textContent = input.label.toLowerCase() + " install failed";
      showBlocker(input.failureText, input.failureOptions);
    } finally {
      input.button.disabled = false;
      input.button.textContent = "Install " + input.label;
    }
  }

  function startDevReload() {
    if (!config.devReload) return;
    window.setInterval(async () => {
      try {
        const response = await fetch(config.reloadUrl, { cache: "no-store" });
        if (!response.ok) return;
        const body = await response.json();
        if (body.serverStartId && body.serverStartId !== config.serverStartId) window.location.reload();
      } catch {}
    }, 900);
  }

  installDir.addEventListener("input", syncPathState);
  selectInstallDir.addEventListener("click", async () => {
    selectInstallDir.disabled = true;
    selectInstallDir.textContent = "Browsing";
    helper.textContent = "Opening folder picker...";
    try {
      const response = await fetch(config.installDirSelectUrl, { method: "POST" });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Folder selection failed");
      installDir.value = body.installDir || installDir.value;
      syncPathState();
      helper.textContent = "Runtime directory selected.";
    } catch (error) {
      helper.textContent = error.message || "Folder selection failed";
    } finally {
      selectInstallDir.disabled = false;
      selectInstallDir.textContent = "Browse";
    }
  });
  resetInstallDir.addEventListener("click", () => {
    installDir.value = installDir.dataset.default;
    syncPathState();
  });
  byId("retry-env").addEventListener("click", checkEnvironment);
  installBunButton.addEventListener("click", installBun);
  installPm2Button.addEventListener("click", installPm2);
  byId("back").addEventListener("click", () => {
    window.location.href = config.backUrl;
  });
  continueButton.addEventListener("click", async () => {
    if (continueButton.disabled || continueButton.classList.contains("busy")) return;
    continueButton.classList.add("busy");
    continueButton.disabled = true;
    continueLabel.textContent = "Saving";
    helper.textContent = "Saving runtime directory to setup-progress.json...";

    try {
      const response = await fetch(config.connectionUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ installDir: installDir.value }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Connection settings could not be saved");
      helper.textContent = "Connection settings saved. Next step: runtime install.";
      railCurrent.textContent = "saved to setup-progress.json";
      continueLabel.textContent = "Saved";
      window.location.href = config.installUrl;
    } catch (error) {
      helper.textContent = error.message || "Connection settings could not be saved";
      continueLabel.textContent = "Continue setup";
      continueButton.classList.remove("busy");
      syncContinue();
    }
  });

  syncPathState();
  checkEnvironment();
  startDevReload();
})();
