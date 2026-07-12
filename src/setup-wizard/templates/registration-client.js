(function(){
  const config = window.__CONSENSUS_SETUP_CONFIG__;
  const byId = (id) => document.getElementById(id);
  const email = byId("email");
  const code = byId("code");
  const port = byId("port");
  const startPm2 = byId("start-pm2");
  const submit = byId("submit");
  const submitLabel = byId("submit-label");
  const helper = byId("helper");
  const railCurrent = byId("rail-current");

  let verificationId = "";
  let model = null;
  let walletPoll = null;

  byId("state-dir").textContent = "state - " + config.progress.stateDir;

  function short(value, head = 7, tail = 5) {
    if (!value) return "not connected";
    if (value.length <= head + tail + 3) return value;
    return value.slice(0, head) + "..." + value.slice(-tail);
  }

  function setPill(id, ok, text) {
    const el = byId(id);
    el.className = "env-status mono " + (ok ? "ok" : "pending");
    el.textContent = text;
  }

  function walletComplete(wallets) {
    return Boolean(wallets && wallets.evmAddress && wallets.solanaAddress && wallets.icpAddress);
  }

  function portValid() {
    const value = Number(port.value.trim());
    return Number.isInteger(value) && value > 0 && value <= 65535;
  }

  function syncReady() {
    if (!model) return;
    const ready = model.emailVerified && walletComplete(model.wallets) && portValid();
    submit.disabled = !ready;
    submitLabel.textContent = ready ? "Complete registration" : "Complete all steps";
    setPill("review-pill", ready, ready ? "Ready" : "Incomplete");
    byId("review-port").textContent = port.value.trim() || "9090";
    if (ready) railCurrent.textContent = "ready to submit registration";
  }

  function render(data) {
    model = data;
    email.value = data.contact || email.value;
    port.value = data.port || port.value || "9090";
    byId("review-email").textContent = data.emailVerified ? data.contact : "not verified";
    byId("review-ipv4").textContent = data.network.publicIpv4 || "pending";
    byId("review-region").textContent = data.network.region
      ? [data.network.region.region, data.network.region.city, data.network.region.country_code].filter(Boolean).join(" · ")
      : "pending";
    setPill("email-pill", data.emailVerified, data.emailVerified ? "Verified" : "Pending");
    if (data.emailVerified) {
      email.disabled = true;
      byId("code-row").hidden = true;
      byId("email-helper").textContent = "Verified contact email.";
    }

    const wallets = data.wallets || {};
    byId("wallet-evm").textContent = short(wallets.evmAddress);
    byId("wallet-solana").textContent = short(wallets.solanaAddress);
    byId("wallet-icp").textContent = short(wallets.icpAddress);
    const connected = [wallets.evmAddress, wallets.solanaAddress, wallets.icpAddress].filter(Boolean).length;
    setPill("wallet-pill", connected === 3, connected + "/3");
    byId("wallet-helper").textContent = connected === 3
      ? "All payout wallets are connected."
      : data.testFlow
        ? "Local test flow will simulate wallet capture."
        : "Open the wallet capture page and connect all three wallets.";
    syncReady();
  }

  async function loadStatus() {
    const response = await fetch(config.statusUrl, { cache: "no-store" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || "Registration status failed");
    render(body);
  }

  async function sendCode() {
    byId("send-code").disabled = true;
    byId("send-code").textContent = "Sending";
    helper.textContent = "Starting email verification...";
    try {
      const response = await fetch(config.emailStartUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: email.value }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Could not send verification code");
      verificationId = body.verification_id;
      byId("code-row").hidden = false;
      if (body.dev_code) code.value = body.dev_code;
      helper.textContent = body.dev_code ? "Test code filled. Verify to continue." : "Verification code sent.";
      railCurrent.textContent = "email code sent";
    } catch (error) {
      helper.textContent = error.message || "Could not send verification code";
    } finally {
      byId("send-code").disabled = false;
      byId("send-code").textContent = "Send code";
    }
  }

  async function verifyCode() {
    byId("verify-code").disabled = true;
    helper.textContent = "Verifying email code...";
    try {
      const response = await fetch(config.emailVerifyUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: email.value, verificationId, code: code.value }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Email verification failed");
      render(body.registration);
      helper.textContent = "Email verified.";
      railCurrent.textContent = "email verified";
    } catch (error) {
      helper.textContent = error.message || "Email verification failed";
    } finally {
      byId("verify-code").disabled = false;
    }
  }

  async function pollWallets(sessionId) {
    const response = await fetch(config.walletStatusUrl + "&session=" + encodeURIComponent(sessionId), { cache: "no-store" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || "Wallet status failed");
    render(body.registration);
    if (body.status === "done") {
      clearInterval(walletPoll);
      walletPoll = null;
      helper.textContent = "Wallet addresses received.";
      railCurrent.textContent = "wallets connected";
    } else if (body.status === "error") {
      clearInterval(walletPoll);
      walletPoll = null;
      helper.textContent = body.error || "Wallet capture failed";
    }
  }

  async function connectWallets() {
    byId("connect-wallets").disabled = true;
    byId("connect-wallets").textContent = "Opening";
    helper.textContent = "Starting wallet capture...";
    try {
      const response = await fetch(config.walletSessionUrl, { method: "POST" });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Wallet capture failed");
      if (body.done) {
        render(body.registration);
        helper.textContent = "Test wallets connected.";
        railCurrent.textContent = "wallets connected";
        return;
      }
      window.open(body.url, "_blank", "noopener,noreferrer");
      helper.textContent = "Wallet page opened. Submit addresses there to continue.";
      railCurrent.textContent = "waiting for wallet capture";
      if (walletPoll) clearInterval(walletPoll);
      walletPoll = window.setInterval(() => pollWallets(body.sessionId).catch((error) => {
        helper.textContent = error.message || "Wallet status failed";
      }), 1200);
    } catch (error) {
      helper.textContent = error.message || "Wallet capture failed";
    } finally {
      byId("connect-wallets").disabled = false;
      byId("connect-wallets").textContent = "Connect wallets";
    }
  }

  async function submitRegistration() {
    submit.classList.add("busy");
    submit.disabled = true;
    helper.textContent = "Submitting node registration...";
    railCurrent.textContent = "submitting registration";
    try {
      const response = await fetch(config.registerUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ port: port.value, startPm2: startPm2.checked }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Registration failed");
      window.location.href = config.successUrl;
    } catch (error) {
      helper.textContent = error.message || "Registration failed";
      submit.classList.remove("busy");
      syncReady();
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
  byId("send-code").addEventListener("click", sendCode);
  byId("verify-code").addEventListener("click", verifyCode);
  byId("connect-wallets").addEventListener("click", connectWallets);
  port.addEventListener("input", syncReady);
  submit.addEventListener("click", submitRegistration);

  loadStatus().catch((error) => {
    helper.textContent = error.message || "Registration status failed";
  });
  startDevReload();
})();
