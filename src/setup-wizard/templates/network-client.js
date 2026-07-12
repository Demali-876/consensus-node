(function(){
  const config = window.__CONSENSUS_SETUP_CONFIG__;
  const byId = (id) => document.getElementById(id);
  const runButton = byId("run");
  const runLabel = byId("run-label");
  const continueButton = byId("continue");
  const helper = byId("helper");
  const railCurrent = byId("rail-current");
  const evalStatus = byId("eval-status");
  const progress = config.progress;

  let testFlow = false;
  let passed = Boolean(progress.evalPassedAt);

  byId("state-dir").textContent = "state - " + progress.stateDir;

  function setText(id, value) {
    byId(id).textContent = value || "not detected";
  }

  function setStatus(state, label) {
    evalStatus.className = "env-status mono " + state;
    evalStatus.textContent = label;
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

  function renderNetwork(body) {
    testFlow = Boolean(body.testFlow);
    const networkDetected = Boolean(body.networkDetected || body.publicIpv4);
    setText("ipv4-value", body.publicIpv4 || "pending");
    setText("ipv6-value", networkDetected ? body.publicIpv6 || "not detected" : "pending");
    const region = body.region
      ? [body.region.region, body.region.city, body.region.country_code].filter(Boolean).join(" · ")
      : "pending";
    setText("region-value", region);

    if (body.publicIpv4) setStep("step-ipv4", "ok", body.publicIpv4);
    if (networkDetected) setStep("step-ipv6", "ok", body.publicIpv6 || "none detected");
    if (body.region) setStep("step-region", "ok", region);
    if (body.evalPassedAt) {
      setStep("step-eval", "ok", "passed at " + body.evalPassedAt);
      setStatus("ok", "Passed");
      railCurrent.textContent = "benchmark passed";
      helper.textContent = "Network benchmark passed. Contact and registration are next.";
      passed = true;
    } else if (body.joinAuthReusable) {
      setStep("step-eval", "ok", "valid join authorization can be reused");
      setStatus("ok", "Reusable");
      railCurrent.textContent = "join authorization available";
      helper.textContent = "A valid join authorization exists. Run the check to confirm this step.";
    } else {
      setStatus("pending", testFlow ? "Test flow" : "Waiting");
      railCurrent.textContent = testFlow ? "local test flow enabled" : "waiting";
      helper.textContent = testFlow
        ? "Local test flow is enabled. This will simulate network and benchmark success."
        : "Ready to detect network reachability and run the benchmark over an encrypted channel.";
    }

    runLabel.textContent = testFlow ? "Simulate pass" : "Run network check";
    continueButton.disabled = !passed;
  }

  async function loadStatus() {
    try {
      const response = await fetch(config.statusUrl, { cache: "no-store" });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Network status failed");
      renderNetwork(body);
    } catch (error) {
      setStatus("err", "Failed");
      helper.textContent = error.message || "Network status failed";
    }
  }

  function setBusy(busy) {
    runButton.classList.toggle("busy", busy);
    runButton.disabled = busy;
    continueButton.disabled = busy || !passed;
  }

  async function runNetwork() {
    setBusy(true);
    passed = false;
    continueButton.disabled = true;
    setStatus("pending", testFlow ? "Simulating" : "Running");
    railCurrent.textContent = testFlow ? "simulating benchmark" : "running benchmark";
    helper.textContent = testFlow ? "Writing local happy-path network progress..." : "Checking network reachability and running the benchmark over an encrypted channel...";
    setStep("step-ipv4", "active", "detecting");
    setStep("step-ipv6", "pending", "queued");
    setStep("step-region", "pending", "queued");
    setStep("step-eval", "pending", "queued");

    try {
      const response = await fetch(config.runUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mode: testFlow ? "test" : "real" }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Network benchmark failed");
      renderNetwork(body.network || {});
    } catch (error) {
      setStep("step-eval", "err", error.message || "network benchmark failed");
      setStatus("err", "Failed");
      railCurrent.textContent = "benchmark failed";
      helper.textContent = error.message || "Network benchmark failed";
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

  byId("back").addEventListener("click", () => {
    window.location.href = config.backUrl;
  });
  runButton.addEventListener("click", runNetwork);
  continueButton.addEventListener("click", () => {
    if (continueButton.disabled) return;
    window.location.href = config.nextUrl;
  });

  loadStatus();
  startDevReload();
})();
