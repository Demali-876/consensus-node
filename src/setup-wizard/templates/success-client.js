(function(){
  const config = window.__CONSENSUS_SETUP_CONFIG__;
  const byId = (id) => document.getElementById(id);
  const helper = byId("helper");
  const pm2Status = byId("pm2-status");

  byId("state-dir").textContent = "state - " + config.progress.stateDir;

  function setText(id, value) {
    byId(id).textContent = value || "not available";
  }

  async function loadStatus() {
    const response = await fetch(config.statusUrl, { cache: "no-store" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || "Could not load success state");
    const cfg = body.config || {};
    setText("node-id", cfg.node_id);
    setText("domain", cfg.domain);
    setText("region", cfg.region || body.network?.region?.region);
    setText("runtime", body.runtimeCurrent);
    setText("state", body.stateDir);
    byId("summary-sub").textContent = cfg.registered_at ? "Registered " + cfg.registered_at : "Registered in local setup state.";
    byId("rail-node").textContent = cfg.node_id || "node ready";
    if (body.runtimeCurrent) byId("start-command").textContent = body.runtimeCurrent + "/scripts/start-pm2.sh";
    helper.textContent = body.testFlow
      ? "Local test flow completed without commissioning this Mac."
      : "Node registration is complete.";
  }

  async function startPm2() {
    const button = byId("start-pm2");
    button.classList.add("busy");
    button.disabled = true;
    pm2Status.className = "env-status mono pending";
    pm2Status.textContent = "Starting";
    helper.textContent = "Starting PM2 control tunnel...";
    try {
      const response = await fetch(config.pm2Url, { method: "POST" });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "PM2 start failed");
      pm2Status.className = "env-status mono ok";
      pm2Status.textContent = "Started";
      helper.textContent = "PM2 control tunnel is started.";
    } catch (error) {
      pm2Status.className = "env-status mono err";
      pm2Status.textContent = "Failed";
      helper.textContent = error.message || "PM2 start failed";
      button.disabled = false;
    } finally {
      button.classList.remove("busy");
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

  document.querySelectorAll(".copy-cmd").forEach((button) => {
    button.addEventListener("click", () => {
      const text = button.previousElementSibling.textContent.trim();
      navigator.clipboard?.writeText(text).then(() => {
        const old = button.textContent;
        button.textContent = "Copied";
        window.setTimeout(() => {
          button.textContent = old;
        }, 1200);
      }).catch(() => {});
    });
  });
  byId("start-pm2").addEventListener("click", startPm2);

  loadStatus().catch((error) => {
    helper.textContent = error.message || "Could not load success state";
  });
  startDevReload();
})();
