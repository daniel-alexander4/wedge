import { browser } from "@/shared/browser";
import type { RuntimeResponse } from "@/shared/types";
import { debugLog } from "@/shared/debug";
import { RUNTIME_MESSAGE_TIMEOUT_MS } from "@/shared/timeouts";

const CHALLENGE_REGEX = /^[A-Za-z0-9_-]{16,256}$/;
const NAMESPACE_REGEX = /^[A-Za-z0-9._:-]{1,64}$/;
const COMPANY_REGEX = /^[A-Za-z0-9._:-]{1,64}$/;

type FormLoginEls = {
  form: HTMLFormElement;
  topLoginBtn: HTMLButtonElement | null;
  username: HTMLInputElement | null;
  signature: HTMLTextAreaElement | null;
  signatureFile: HTMLInputElement | null;
  challenge: HTMLInputElement | null;
  company: HTMLInputElement | null;
  namespace: HTMLInputElement | null;
};

function findFormLoginElements(): FormLoginEls | null {
  const form = document.getElementById("auth-verify-form") as HTMLFormElement | null;
  if (!form) return null;
  return {
    form,
    topLoginBtn: document.getElementById("login-submit-btn") as HTMLButtonElement | null,
    username: form.querySelector('input[name="username"]') as HTMLInputElement | null,
    signature: form.querySelector('textarea[name="signature"]') as HTMLTextAreaElement | null,
    signatureFile: form.querySelector('input[name="signature_file"]') as HTMLInputElement | null,
    challenge: form.querySelector('input[name="ssh_challenge"]') as HTMLInputElement | null,
    company: form.querySelector('input[name="ssh_company"]') as HTMLInputElement | null,
    namespace: form.querySelector('input[name="ssh_namespace"]') as HTMLInputElement | null
  };
}

function isFormLoginPage(): boolean {
  return window.location.pathname === "/login" && Boolean(document.getElementById("auth-verify-form"));
}

function isTrustedFormLoginPage(els: FormLoginEls): boolean {
  const formMethod = String(els.form.getAttribute("method") || "").trim().toLowerCase();
  const rawAction = String(els.form.getAttribute("action") || "").trim();
  let actionPath = "";
  let actionOrigin = "";
  try {
    const u = new URL(rawAction || "", window.location.origin);
    actionPath = u.pathname;
    actionOrigin = u.origin;
  } catch {
    return false;
  }

  const namespace = String(els.namespace?.value || "").trim();
  const company = String(els.company?.value || "").trim();
  const challenge = String(els.challenge?.value || "").trim();

  const formTarget = String(els.form.getAttribute("target") || "").trim();

  return (
    formMethod === "post" &&
    actionPath === "/auth/verify" &&
    actionOrigin === window.location.origin &&
    (!formTarget || formTarget === "_self") &&
    (!company || COMPANY_REGEX.test(company)) &&
    NAMESPACE_REGEX.test(namespace) &&
    CHALLENGE_REGEX.test(challenge)
  );
}

function showSuccessToast(): void {
  const existing = document.getElementById("ssh-auth-success-toast");
  if (existing) existing.remove();
  const toast = document.createElement("div");
  toast.id = "ssh-auth-success-toast";
  toast.textContent = "Signed in with SSH key";
  toast.style.cssText =
    "position:fixed;top:24px;right:24px;z-index:2147483647;" +
    "background:#0f2a1e;color:#6ee7a0;border:1px solid #249b68;" +
    "border-radius:8px;padding:12px 20px;font:14px/1.4 system-ui,sans-serif;" +
    "box-shadow:0 4px 16px rgba(0,0,0,.4);opacity:0;transition:opacity .2s;";
  document.body.appendChild(toast);
  requestAnimationFrame(() => { toast.style.opacity = "1"; });
  window.setTimeout(() => {
    toast.style.opacity = "0";
    window.setTimeout(() => toast.remove(), 200);
  }, 3000);
}

function showFormError(form: HTMLFormElement, message: string): void {
  let node = form.querySelector(".ssh-auth-bridge-error") as HTMLDivElement | null;
  if (!node) {
    node = document.createElement("div");
    node.className = "notice notice-danger ssh-auth-bridge-error";
    node.style.whiteSpace = "pre-line";
    form.prepend(node);
  }
  node.textContent = message;
}

function errorBlock(cause: string, action: string): string {
  return `ERROR\nCause: ${cause}\nAction: ${action}`;
}

function normalizeErrorMessage(raw: unknown): string {
  const msg = String(raw || "").trim();
  if (!msg) {
    return errorBlock(
      "SSH auth extension could not sign the challenge.",
      "Check extension settings and retry."
    );
  }
  if (msg.startsWith("ERROR\n")) return msg;

  const lower = msg.toLowerCase();
  if (lower.includes("origin not allowed")) {
    return errorBlock(
      `Origin not allowed for ${window.location.origin}.`,
      "Add an Origin mappings entry in extension Preferences (e.g. https://localhost:8443 myapp)."
    );
  }
  if (lower.includes("invalid namespace")) {
    return msg;
  }
  if (lower.includes("no namespace configured for origin")) {
    return errorBlock(
      `No namespace configured for ${window.location.origin}.`,
      "Add an Origin mappings entry in extension Preferences."
    );
  }
  if (lower.includes("invalid challenge format")) {
    return errorBlock(
      "Challenge format is invalid.",
      "Refresh the login page and try again."
    );
  }
  if (lower.includes("no such native application")) {
    return errorBlock(
      "Native host 'com.pubkey.auth' is not installed or not registered.",
      "Install or repair the native host and retry."
    );
  }
  if (lower.includes("key file not found")) {
    return errorBlock(
      "SSH private key file was not found.",
      "Update 'SSH private key path' in extension Preferences."
    );
  }
  if (lower.includes("permissions are too open")) {
    return errorBlock(
      "SSH private key permissions are too open.",
      "Run: chmod 600 <your-key-path> and retry."
    );
  }
  if (lower.includes("not owned by current user")) {
    return errorBlock(
      "SSH private key is not owned by the current user.",
      "Fix key ownership or choose a key owned by your account."
    );
  }
  if (lower.includes("extension context invalidated") || lower.includes("context invalidated")) {
    return errorBlock(
      "Extension was reloaded or updated.",
      "Refresh this page and try again."
    );
  }
  if (lower.includes("extension disabled")) {
    return errorBlock(
      "SSH auth extension is disabled.",
      "Enable the extension in Preferences and try again."
    );
  }

  return errorBlock(`Signing failed: ${msg}`, "Check extension settings and retry.");
}

async function requestSignature(challenge: string, namespace: string, company?: string): Promise<string> {
  const messagePromise = browser.runtime.sendMessage({
    type: "SIGN_CHALLENGE",
    challenge,
    namespace,
    company,
    origin: window.location.origin
  }) as Promise<RuntimeResponse>;
  const timeoutPromise = new Promise<RuntimeResponse>((resolve) => {
    window.setTimeout(() => resolve({ ok: false, error: "Signing request timed out" }), RUNTIME_MESSAGE_TIMEOUT_MS);
  });
  const response = await Promise.race([messagePromise, timeoutPromise]);
  if (!response.ok) {
    throw new Error(response.error || "Extension could not sign challenge");
  }
  const signature = String(response.signature || "").trim();
  if (!signature) {
    throw new Error("Received empty signature from extension");
  }
  return signature;
}

function shouldAutoSign(els: FormLoginEls): boolean {
  const signatureText = String(els.signature?.value || "").trim();
  const hasSignatureFile = Boolean(els.signatureFile?.files && els.signatureFile.files.length > 0);
  return signatureText.length === 0 && !hasSignatureFile;
}

function canAttempt(els: FormLoginEls): { ok: boolean; reason?: string } {
  if (!els.username || !String(els.username.value || "").trim()) {
    return { ok: false, reason: "Username is required before extension login." };
  }
  if (!els.signature) {
    return { ok: false, reason: "Signature field not found." };
  }
  const challenge = String(els.challenge?.value || "").trim();
  const company = String(els.company?.value || "").trim();
  const namespace = String(els.namespace?.value || "").trim();
  if (!challenge || !namespace) {
    return { ok: false, reason: "Challenge data missing in login form." };
  }
  return { ok: true };
}

async function autoSignAndSubmit(els: FormLoginEls, trustedGesture: boolean): Promise<void> {
  if (els.form.dataset.sshAuthBridgeBusy === "1") return;
  if (!trustedGesture) {
    showFormError(
      els.form,
      errorBlock("Signing requires a direct user action.", "Click Login again to authorize signing.")
    );
    return;
  }
  const verdict = canAttempt(els);
  if (!verdict.ok) {
    if (verdict.reason) showFormError(els.form, verdict.reason);
    return;
  }
  if (!shouldAutoSign(els)) {
    els.form.requestSubmit();
    return;
  }

  const challenge = String(els.challenge?.value || "").trim();
  const company = String(els.company?.value || "").trim();
  const namespace = String(els.namespace?.value || "").trim();
  debugLog("content", "attempting sign", { origin: window.location.origin, namespace, hasCompany: Boolean(company) });

  els.form.dataset.sshAuthBridgeBusy = "1";
  try {
    const signature = await requestSignature(challenge, namespace, company || undefined);
    if (!els.signature) {
      showFormError(els.form, errorBlock("Form structure changed unexpectedly.", "Refresh the page and try again."));
      return;
    }
    els.signature.value = signature;
    showSuccessToast();
    els.form.dataset.sshAuthBridgeSubmit = "1";
    els.form.requestSubmit();
  } catch (error) {
    debugLog("content", "signing failed", error instanceof Error ? error.message : String(error));
    showFormError(els.form, normalizeErrorMessage(error instanceof Error ? error.message : String(error)));
  } finally {
    els.form.dataset.sshAuthBridgeBusy = "0";
  }
}

// ---------------------------------------------------------------------------
// Form bridge (traditional form-based login with #auth-verify-form)
// ---------------------------------------------------------------------------

async function installFormBridge(): Promise<void> {
  const status = (await browser.runtime.sendMessage({ type: "GET_STATUS" })) as RuntimeResponse;
  if (!status.ok || status.enabled === false) return;
  if (!isFormLoginPage()) return;

  const els = findFormLoginElements();
  if (!els) return;
  if (!isTrustedFormLoginPage(els)) return;

  els.form.addEventListener(
    "submit",
    (event) => {
      if (els.form.dataset.sshAuthBridgeSubmit === "1") {
        els.form.dataset.sshAuthBridgeSubmit = "0";
        return;
      }
      if (!shouldAutoSign(els)) return;
      if (!event.isTrusted) return;
      event.preventDefault();
      void autoSignAndSubmit(els, true);
    },
    true
  );

  if (els.topLoginBtn) {
    els.topLoginBtn.addEventListener(
      "click",
      (event) => {
        if (!shouldAutoSign(els)) return;
        if (!event.isTrusted) return;
        event.preventDefault();
        void autoSignAndSubmit(els, true);
      },
      true
    );
  }

}

// ---------------------------------------------------------------------------
// SPA bridge (challenge modal with data attributes)
// ---------------------------------------------------------------------------

type SPALoginEls = {
  challengeModal: HTMLElement;
  signatureInput: HTMLTextAreaElement;
  verifyBtn: HTMLButtonElement;
};

function findSPALoginElements(): SPALoginEls | null {
  const challengeModal = document.getElementById("challenge-modal");
  if (!challengeModal) return null;
  const signatureInput = document.getElementById("signature-input") as HTMLTextAreaElement | null;
  const verifyBtn = document.getElementById("verify-btn") as HTMLButtonElement | null;
  if (!signatureInput || !verifyBtn) return null;
  return { challengeModal, signatureInput, verifyBtn };
}

function isTrustedSPAChallenge(modal: HTMLElement): { challenge: string; namespace: string } | null {
  const challenge = String(modal.dataset.sshChallenge || "").trim();
  const namespace = String(modal.dataset.sshNamespace || "").trim();
  if (!challenge || !namespace) return null;
  if (!CHALLENGE_REGEX.test(challenge)) return null;
  if (!NAMESPACE_REGEX.test(namespace)) return null;
  return { challenge, namespace };
}

function showSPAError(modal: HTMLElement, message: string): void {
  clearSPAError(modal);
  const node = document.createElement("div");
  node.className = "ssh-auth-bridge-error";
  node.style.cssText = "background:#2a1215;color:#f87171;border:1px solid #991b1b;border-radius:6px;padding:10px 14px;margin:8px 0;white-space:pre-line;font-size:0.9em;";
  node.textContent = message;
  const actions = modal.querySelector(".modal-actions");
  if (actions) {
    actions.parentNode!.insertBefore(node, actions);
  } else {
    modal.appendChild(node);
  }
}

function clearSPAError(modal: HTMLElement): void {
  modal.querySelectorAll(".ssh-auth-bridge-error").forEach((el) => el.remove());
}

async function autoSignAndSubmitSPA(els: SPALoginEls): Promise<void> {
  if (els.challengeModal.dataset.sshAuthBridgeBusy === "1") return;

  const trusted = isTrustedSPAChallenge(els.challengeModal);
  if (!trusted) return;

  debugLog("content", "SPA attempting sign", { origin: window.location.origin, namespace: trusted.namespace });

  els.challengeModal.dataset.sshAuthBridgeBusy = "1";
  clearSPAError(els.challengeModal);
  try {
    const signature = await requestSignature(trusted.challenge, trusted.namespace);

    // Stale check: modal may have been closed or challenge changed while awaiting
    const currentTrusted = isTrustedSPAChallenge(els.challengeModal);
    if (!currentTrusted || currentTrusted.challenge !== trusted.challenge) {
      debugLog("content", "SPA challenge became stale, aborting");
      return;
    }
    if (els.challengeModal.classList.contains("hidden")) return;

    els.signatureInput.value = signature;
    els.signatureInput.dispatchEvent(new Event("input", { bubbles: true }));
    showSuccessToast();
    els.verifyBtn.click();
  } catch (error) {
    debugLog("content", "SPA signing failed", error instanceof Error ? error.message : String(error));
    showSPAError(els.challengeModal, normalizeErrorMessage(error instanceof Error ? error.message : String(error)));
  } finally {
    els.challengeModal.dataset.sshAuthBridgeBusy = "0";
  }
}

async function installSPABridge(): Promise<void> {
  const status = (await browser.runtime.sendMessage({ type: "GET_STATUS" })) as RuntimeResponse;
  if (!status.ok || status.enabled === false) return;

  const els = findSPALoginElements();
  if (!els) return;

  debugLog("content", "SPA bridge installed", { origin: window.location.origin });

  // Gate signing behind a trusted user gesture on the verify button
  els.verifyBtn.addEventListener(
    "click",
    (event) => {
      if (!event.isTrusted) return;
      if (els.challengeModal.classList.contains("hidden")) return;
      if (!isTrustedSPAChallenge(els.challengeModal)) return;
      if (els.challengeModal.dataset.sshAuthBridgeBusy === "1") return;
      if (els.signatureInput.value.trim()) return;
      event.preventDefault();
      void autoSignAndSubmitSPA(els);
    },
    true
  );
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

function boot(): void {
  const run = () => {
    void installFormBridge();
    void installSPABridge();
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", run, { once: true });
  } else {
    run();
  }
}

boot();
