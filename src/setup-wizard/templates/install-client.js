(function(){
  const config = window.__CONSENSUS_SETUP_CONFIG__;
  const byId = (id) => document.getElementById(id);
  const progress = config.progress;
  const manifestGrid = byId("manifest-grid");
  const manifestStatus = byId("manifest-status");
  const manifestSource = byId("manifest-source");
  const reuseCard = byId("reuse-card");
  const reuseCopy = byId("reuse-copy");
  const reuseMode = byId("reuse-mode");
  const installMode = byId("install-mode");
  const continueButton = byId("continue");
  const continueLabel = byId("continue-label");
  const helper = byId("helper");
  const railCurrent = byId("rail-current");

  let installModeValue = "install";
  let manifestReady = false;
  let installDone = false;

  byId("state-dir").textContent = "state - " + progress.stateDir;

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function trunc(value, size = 20) {
    const text = String(value || "not provided");
    if (text.length <= size) return text;
    const edge = Math.max(6, Math.floor((size - 3) / 2));
    return text.slice(0, edge) + "..." + text.slice(-edge);
  }

  function setManifestStatus(state, text) {
    manifestStatus.className = "env-status mono " + state;
    manifestStatus.textContent = text;
  }

  function renderManifest(data) {
    const manifest = data.manifest || {};
    const rows = [
      ["Version", manifest.version],
      ["Platform", manifest.platform],
      ["Commit", manifest.commit],
      ["SHA-256", manifest.sha256],
      ["Source", manifest.source],
    ];
    manifestGrid.innerHTML = rows.map(([key, value]) => {
      const full = value || "not provided";
      return '<div class="kv-row"><span class="kv-key mono">' + escapeHtml(key) + '</span><span class="kv-value mono" title="' + escapeHtml(full) + '">' + escapeHtml(trunc(full, key === "Source" ? 54 : 34)) + '</span></div>';
    }).join("");
    manifestSource.textContent = data.serverUrl + " - fetched just now";
    setManifestStatus("ok", "Verified");

    if (data.canReuse) {
      reuseCard.hidden = false;
      reuseCopy.textContent = data.reuseReason || "A matching runtime is already installed.";
      setMode("reuse");
    } else {
      reuseCard.hidden = true;
      setMode("install");
    }

    manifestReady = true;
    continueButton.disabled = false;
    syncContinueLabel();
    helper.textContent = data.canReuse
      ? "A matching runtime is available. Reuse it or reinstall fresh."
      : "Approved release is ready to download and install.";
    railCurrent.textContent = data.canReuse ? "existing runtime detected" : "manifest verified";
  }

  function setMode(mode) {
    installModeValue = mode;
    reuseMode.classList.toggle("on", mode === "reuse");
    installMode.classList.toggle("on", mode === "install");
    syncContinueLabel();
  }

  function syncContinueLabel() {
    if (installDone) {
      continueLabel.textContent = "Continue to network detection";
    } else if (!manifestReady) {
      continueLabel.textContent = "Fetching manifest";
    } else {
      continueLabel.textContent = installModeValue === "reuse" ? "Use existing runtime" : "Download & install";
    }
  }

  function setStep(id, state, detail) {
    const row = byId(id);
    const icon = row.querySelector(".env-icon");
    const sub = row.querySelector(".step-sub");
    const glyph = state === "ok" ? "✓" : state === "err" ? "!" : "-";
    row.className = "install-step " + state;
    icon.className = "env-icon " + (state === "active" ? "busy" : state === "ok" ? "ok" : state === "err" ? "err" : "pending");
    icon.querySelector(".estatic").textContent = glyph;
    sub.textContent = detail;
  }

  function setBusy(busy) {
    continueButton.classList.toggle("busy", busy);
    continueButton.disabled = busy || !manifestReady;
  }

  async function loadManifest() {
    setManifestStatus("pending", "Fetching");
    helper.textContent = "Fetching approved release manifest...";
    try {
      const response = await fetch(config.manifestUrl, { cache: "no-store" });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Manifest fetch failed");
      renderManifest(body);
    } catch (error) {
      setManifestStatus("err", "Failed");
      manifestSource.textContent = "Manifest could not be fetched.";
      helper.textContent = error.message || "Manifest fetch failed";
      railCurrent.textContent = "manifest fetch failed";
    }
  }

  async function runInstall() {
    setBusy(true);
    helper.textContent = installModeValue === "reuse" ? "Confirming existing runtime..." : "Installing approved runtime...";
    railCurrent.textContent = installModeValue === "reuse" ? "using existing runtime" : "downloading verified artifact";
    setStep("step-download", installModeValue === "reuse" ? "ok" : "active", installModeValue === "reuse" ? "skipped - existing artifact" : "downloading and verifying artifact");
    setStep("step-verify", "pending", installModeValue === "reuse" ? "skipped" : "queued");
    setStep("step-install", "pending", installModeValue === "reuse" ? "skipped" : "queued");

    try {
      const response = await fetch(config.installUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: installModeValue }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Runtime install failed");

      setStep("step-download", "ok", installModeValue === "reuse" ? "existing runtime selected" : "downloaded and checksum verified");
      setStep("step-verify", "ok", installModeValue === "reuse" ? "existing release matches manifest" : "checksum matches manifest");
      setStep("step-install", "ok", (body.install && body.install.currentPath) ? "ready at " + body.install.currentPath : "runtime ready");
      installDone = true;
      railCurrent.textContent = "runtime install confirmed";
      helper.textContent = "Runtime ready. Network reachability and benchmark are next.";
      syncContinueLabel();
    } catch (error) {
      setStep("step-install", "err", error.message || "runtime install failed");
      railCurrent.textContent = "runtime install failed";
      helper.textContent = error.message || "Runtime install failed";
    } finally {
      setBusy(false);
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

  reuseMode.addEventListener("click", () => setMode("reuse"));
  installMode.addEventListener("click", () => setMode("install"));
  byId("back").addEventListener("click", () => {
    window.location.href = config.backUrl;
  });
  continueButton.addEventListener("click", async () => {
    if (continueButton.disabled || continueButton.classList.contains("busy")) return;
    if (installDone) {
      window.location.href = config.nextUrl;
      return;
    }
    await runInstall();
  });

  loadManifest();
  startDevReload();
})();
