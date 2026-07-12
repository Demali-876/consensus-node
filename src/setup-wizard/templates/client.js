(function(){
  const config = window.__CONSENSUS_SETUP_CONFIG__;
  const byId = (id) => document.getElementById(id);
  const agree = byId("agree-check");
  const signature = byId("signature");
  const confirmation = byId("confirmation");
  const button = byId("continue");
  const helper = byId("helper");
  const reviewGate = byId("agreement-review-gate");
  const reviewStatus = byId("agreement-review-status");
  const reviewButton = byId("review-agreement");
  const modal = byId("agreement-modal");
  const modalClose = byId("agreement-modal-close");
  const modalScroll = byId("agreement-modal-scroll");
  const modalAgree = byId("agreement-modal-agree");
  const scrollFill = byId("agreement-scroll-fill");
  const scrollNote = byId("agreement-scroll-note");
  const progress = config.progress;
  const storageKey = "consensus-operator-agreement-reviewed:" + config.agreementVersion;
  let agreementReviewed = progress.operatorAgreementAccepted || window.sessionStorage.getItem(storageKey) === "1";

  byId("state-dir").textContent = "state - " + progress.stateDir;
  const progressLine = byId("progress-line");
  if (progressLine) {
    progressLine.textContent = progress.operatorAgreementAccepted
      ? "accepted"
      : progress.hasProgress
      ? "prior state found"
      : "review and sign";
  }

  if (progress.hasProgress) {
    helper.textContent = progress.lastCompletedLabel
      ? "Prior setup state found. Last completed step: " + progress.lastCompletedLabel + "."
      : "Prior setup state found. Continue from the current required step.";
  }

  if (progress.operatorAgreementAccepted) {
    agree.checked = true;
    signature.value = progress.operatorAgreementSignature || "";
    confirmation.value = "I AGREE";
    helper.textContent = "Agreement accepted " + (progress.operatorAgreementAcceptedAt || "in a prior run") + ".";
  } else if (progress.operatorAgreementVersion && progress.operatorAgreementVersion !== config.agreementVersion) {
    helper.textContent = "Agreement was updated. Review the current agreement before signing.";
  }

  function markAgreementReviewed(options = {}) {
    agreementReviewed = true;
    window.sessionStorage.setItem(storageKey, "1");
    agree.checked = true;
    agree.disabled = false;
    reviewGate.classList.add("accepted");
    reviewStatus.textContent = "Agreement accepted - signature required";
    if (!options.preserveHelper) helper.textContent = "Agreement accepted in this session. Add signature and confirmation to continue.";
    sync();
  }

  function openModal() {
    modal.hidden = false;
    modalScroll.focus();
    requestAnimationFrame(syncModalScroll);
  }

  function closeModal() {
    modal.hidden = true;
    reviewButton.focus();
  }

  function syncModalScroll() {
    const max = Math.max(1, modalScroll.scrollHeight - modalScroll.clientHeight);
    const reachedEnd = modalScroll.scrollTop + modalScroll.clientHeight >= modalScroll.scrollHeight - 8;
    const progressValue = reachedEnd ? 1 : Math.min(1, Math.max(0, modalScroll.scrollTop / max));
    scrollFill.style.width = Math.round(progressValue * 100) + "%";
    modalAgree.disabled = !reachedEnd;
    scrollNote.textContent = reachedEnd ? "End reached" : "Scroll to continue";
  }

  function valid() {
    return agreementReviewed
      && agree.checked
      && signature.value.trim().length > 1
      && confirmation.value.trim() === "I AGREE";
  }

  function sync() {
    agree.disabled = !agreementReviewed;
    button.disabled = !valid();
  }

  if (agreementReviewed) markAgreementReviewed({ preserveHelper: progress.operatorAgreementAccepted });

  reviewButton.addEventListener("click", openModal);
  modalClose.addEventListener("click", closeModal);
  modal.addEventListener("click", (event) => {
    if (event.target === modal) closeModal();
  });
  modalScroll.addEventListener("scroll", syncModalScroll);
  modalAgree.addEventListener("click", () => {
    if (modalAgree.disabled) return;
    markAgreementReviewed();
    closeModal();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !modal.hidden) closeModal();
  });

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

  [agree, signature, confirmation].forEach((el) => el.addEventListener("input", sync));
  agree.addEventListener("change", sync);
  button.addEventListener("click", async () => {
    if (!valid() || button.classList.contains("busy")) return;
    button.classList.add("busy");
    button.disabled = true;
    byId("continue-label").textContent = "Recording agreement";
    helper.textContent = "Writing agreement to setup-progress.json...";
    try {
      const response = await fetch(config.agreementUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          accepted: agree.checked,
          agreementReviewed,
          signature: signature.value,
          confirmation: confirmation.value,
        }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.error || "Agreement could not be recorded");
      helper.textContent = "Agreement recorded. Next step: runtime directory and local tool checks.";
      byId("continue-label").textContent = "Agreement recorded";
      setTimeout(() => {
        window.location.href = config.nextUrl;
      }, 500);
    } catch (error) {
      helper.textContent = error.message || "Agreement could not be recorded";
      button.classList.remove("busy");
      button.disabled = false;
      byId("continue-label").textContent = "Continue setup";
    }
  });

  startDevReload();
  sync();
})();
