import { browser } from "@/shared/browser";
import type { OriginScope, OriginScopesMap, RuntimeResponse } from "@/shared/types";
import { debugLog } from "@/shared/debug";
import { RUNTIME_MESSAGE_TIMEOUT_MS } from "@/shared/timeouts";

const NAMESPACE_REGEX = /^[A-Za-z0-9._:-]{1,64}$/;
const MAX_ORIGIN_ROWS = 100;

const KEY_PATHS = {
  ed25519: "~/.ssh/id_ed25519",
  rsa: "~/.ssh/id_rsa",
  ecdsa: "~/.ssh/id_ecdsa"
} as const;
type KeyType = keyof typeof KEY_PATHS;

async function safeSendMessage(message: unknown, timeoutMs = RUNTIME_MESSAGE_TIMEOUT_MS): Promise<RuntimeResponse> {
  let timeoutId: number | null = null;
  const timeoutPromise = new Promise<RuntimeResponse>((resolve) => {
    timeoutId = window.setTimeout(() => resolve({ ok: false, error: "Extension message timed out" }), timeoutMs);
  });
  const messagePromise = (browser.runtime.sendMessage(message) as Promise<RuntimeResponse>).catch((error: unknown) => ({
    ok: false,
    error: error instanceof Error ? error.message : String(error)
  }));
  const response = (await Promise.race([messagePromise, timeoutPromise])) as RuntimeResponse;
  if (timeoutId !== null) window.clearTimeout(timeoutId);
  debugLog("onboarding", "runtime message result", { ok: response.ok, error: response.error || null });
  return response;
}

function detectOS(): "linux" | "macos" | "windows" {
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes("win")) return "windows";
  if (ua.includes("mac")) return "macos";
  return "linux";
}

function getInstallCommand(extId: string): string {
  const os = detectOS();
  switch (os) {
    case "windows":
      return `cd native-host && powershell -File install-windows.ps1 -ExtensionId ${extId}`;
    case "macos":
      return `cd native-host && ./install-macos.sh --extension-id ${extId}`;
    default:
      return `cd native-host && ./install-linux.sh --extension-id ${extId}`;
  }
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

function activateStep(stepNum: number): void {
  for (let i = 1; i <= 3; i++) {
    const el = document.getElementById(`step-${i}`);
    if (!el) continue;
    el.classList.remove("active");
    if (i === stepNum) el.classList.add("active");
  }
}

function markStepDone(stepNum: number, statusText: string): void {
  const el = document.getElementById(`step-${stepNum}`);
  const statusEl = document.getElementById(`step-${stepNum}-status`);
  if (el) el.classList.add("done");
  if (statusEl) statusEl.textContent = statusText;
}

function showResult(containerId: string, pass: boolean, text: string): void {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.hidden = false;
  el.className = `step-result ${pass ? "result-pass" : "result-fail"}`;
  el.textContent = text;
}

// ---------------------------------------------------------------------------
// Target system rows (same logic as popup)
// ---------------------------------------------------------------------------

function createOriginRow(origin = "", namespace = "", port = ""): HTMLDivElement {
  const row = document.createElement("div");
  row.className = "origin-row";

  const originInput = document.createElement("input");
  originInput.type = "text";
  originInput.placeholder = "https://example.com";
  originInput.value = origin;
  originInput.className = "origin-input";
  originInput.addEventListener("input", () => validateOriginRow(row));

  const portInput = document.createElement("input");
  portInput.type = "text";
  portInput.placeholder = "port";
  portInput.value = port;
  portInput.className = "port-input";
  portInput.addEventListener("input", () => validateOriginRow(row));

  const nsInput = document.createElement("input");
  nsInput.type = "text";
  nsInput.placeholder = "namespace";
  nsInput.value = namespace;
  nsInput.className = "namespace-input";
  nsInput.addEventListener("input", () => validateOriginRow(row));

  const removeBtn = document.createElement("span");
  removeBtn.className = "remove-row-btn";
  removeBtn.textContent = "\uD83D\uDDD1";
  removeBtn.setAttribute("role", "button");
  removeBtn.tabIndex = 0;
  removeBtn.addEventListener("click", () => row.remove());

  row.appendChild(originInput);
  row.appendChild(portInput);
  row.appendChild(nsInput);
  row.appendChild(removeBtn);
  return row;
}

function validateOriginRow(row: HTMLDivElement): boolean {
  const originInput = row.querySelector(".origin-input") as HTMLInputElement;
  const portInput = row.querySelector(".port-input") as HTMLInputElement;
  const nsInput = row.querySelector(".namespace-input") as HTMLInputElement;
  let valid = true;

  const rawOrigin = originInput.value.trim();
  if (rawOrigin) {
    try { new URL(rawOrigin); originInput.classList.remove("invalid"); }
    catch { originInput.classList.add("invalid"); valid = false; }
  } else {
    originInput.classList.remove("invalid");
  }

  const portVal = portInput.value.trim();
  if (portVal) {
    const portNum = Number(portVal);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      portInput.classList.add("invalid"); valid = false;
    } else {
      portInput.classList.remove("invalid");
    }
  } else {
    portInput.classList.remove("invalid");
  }

  const nsVal = nsInput.value.trim();
  if (nsVal && !NAMESPACE_REGEX.test(nsVal)) {
    nsInput.classList.add("invalid"); valid = false;
  } else {
    nsInput.classList.remove("invalid");
  }

  return valid;
}

function collectOriginScopes(): { values: OriginScopesMap; invalidLines: string[] } {
  const container = document.getElementById("origin-rows");
  const out: OriginScopesMap = {};
  const invalidLines: string[] = [];
  if (!container) return { values: out, invalidLines };

  const rows = container.querySelectorAll(".origin-row");
  if (rows.length > MAX_ORIGIN_ROWS) {
    return { values: out, invalidLines: [`Too many target systems (max ${MAX_ORIGIN_ROWS})`] };
  }

  for (const row of rows) {
    const originInput = row.querySelector(".origin-input") as HTMLInputElement;
    const portInput = row.querySelector(".port-input") as HTMLInputElement;
    const nsInput = row.querySelector(".namespace-input") as HTMLInputElement;
    const rawHost = originInput.value.trim();
    const rawPort = portInput.value.trim();
    const nsVal = nsInput.value.trim();
    if (!rawHost && !nsVal && !rawPort) continue;

    if (!rawHost || !nsVal) {
      invalidLines.push(`${rawHost || "(empty host)"} — host and namespace are required`);
      continue;
    }

    if (rawPort) {
      const portNum = Number(rawPort);
      if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
        invalidLines.push(`${rawHost} — invalid port "${rawPort}"`);
        continue;
      }
    }

    const fullUrl = rawPort ? `${rawHost}:${rawPort}` : rawHost;
    let origin = "";
    try { origin = new URL(fullUrl).origin; }
    catch { invalidLines.push(`${fullUrl} — invalid URL`); continue; }

    if (!NAMESPACE_REGEX.test(nsVal)) { invalidLines.push(`${rawHost} — invalid namespace`); continue; }

    if (!out[origin]) out[origin] = [];
    const candidate: OriginScope = { namespace: nsVal };
    const exists = out[origin].some(
      (e) => e.namespace === candidate.namespace
    );
    if (!exists) out[origin].push(candidate);
  }
  return { values: out, invalidLines };
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

async function init(): Promise<void> {
  if (document.readyState === "loading") {
    await new Promise<void>((r) => document.addEventListener("DOMContentLoaded", () => r(), { once: true }));
  }

  const extId = browser.runtime.id || "";
  const extIdEl = document.getElementById("ext-id");
  const installCmdEl = document.getElementById("install-cmd") as HTMLPreElement | null;
  const copyCmdBtn = document.getElementById("copy-cmd") as HTMLButtonElement | null;
  const checkNativeBtn = document.getElementById("check-native-btn") as HTMLButtonElement | null;
  const keyPathInput = document.getElementById("key-path") as HTMLInputElement | null;
  const validateKeyBtn = document.getElementById("validate-key-btn") as HTMLButtonElement | null;
  const addRowBtn = document.getElementById("add-origin-row") as HTMLButtonElement | null;
  const originRows = document.getElementById("origin-rows") as HTMLDivElement | null;
  const saveFinishBtn = document.getElementById("save-and-finish") as HTMLButtonElement | null;
  const statusEl = document.getElementById("status") as HTMLDivElement | null;
  const keyTabs = Array.from(document.querySelectorAll("[data-key-type]")) as HTMLButtonElement[];

  if (extIdEl) extIdEl.textContent = extId;
  if (installCmdEl) installCmdEl.textContent = getInstallCommand(extId);

  // Make step headers toggle visibility
  for (let i = 1; i <= 3; i++) {
    const header = document.querySelector(`#step-${i} .step-header`);
    if (header) {
      header.addEventListener("click", () => activateStep(i));
    }
  }

  // Copy command
  if (copyCmdBtn && installCmdEl) {
    copyCmdBtn.addEventListener("click", () => {
      void navigator.clipboard.writeText(installCmdEl.textContent || "").then(() => {
        copyCmdBtn.textContent = "Copied!";
        window.setTimeout(() => { copyCmdBtn.textContent = "Copy"; }, 1500);
      });
    });
  }

  // Step 1: Check native host
  if (checkNativeBtn) {
    checkNativeBtn.addEventListener("click", async () => {
      checkNativeBtn.textContent = "Checking...";
      checkNativeBtn.disabled = true;
      const resp = await safeSendMessage({ type: "PING_NATIVE" });
      const connected = resp.ok && resp.nativeHostConnected === true;
      showResult("native-result", connected, connected ? "Connected!" : `Not connected: ${resp.error || "unknown error"}`);
      if (connected) {
        markStepDone(1, "Connected");
        activateStep(2);
      }
      checkNativeBtn.textContent = "Check Connection";
      checkNativeBtn.disabled = false;
    });
  }

  // Step 2: Key type tabs
  for (const tab of keyTabs) {
    tab.addEventListener("click", () => {
      const type = (tab.dataset.keyType || "") as KeyType;
      if (!KEY_PATHS[type] || !keyPathInput) return;
      keyPathInput.value = KEY_PATHS[type];
      for (const t of keyTabs) {
        t.setAttribute("aria-pressed", t === tab ? "true" : "false");
      }
    });
  }

  // Step 2: Validate key
  if (validateKeyBtn) {
    validateKeyBtn.addEventListener("click", async () => {
      validateKeyBtn.textContent = "Validating...";
      validateKeyBtn.disabled = true;

      // First save the key path so VALIDATE_KEY uses it
      const kp = keyPathInput?.value.trim() || "~/.ssh/id_ed25519";
      await safeSendMessage({ type: "SET_CONFIG", keyPath: kp });

      const resp = await safeSendMessage({ type: "VALIDATE_KEY" });
      const keyOk = resp.ok && resp.keyValid === true;
      showResult("key-result", keyOk, keyOk ? "Key is valid!" : `Key error: ${resp.keyError || "validation failed"}`);
      if (keyOk) {
        markStepDone(2, "Valid");
        activateStep(3);
      }
      validateKeyBtn.textContent = "Validate Key";
      validateKeyBtn.disabled = false;
    });
  }

  // Step 3: Origin rows
  if (originRows) {
    originRows.appendChild(createOriginRow());
  }
  if (addRowBtn && originRows) {
    addRowBtn.addEventListener("click", () => {
      originRows.appendChild(createOriginRow());
    });
  }

  // Save & Finish
  if (saveFinishBtn) {
    saveFinishBtn.addEventListener("click", async () => {
      const parsed = collectOriginScopes();
      const errorsEl = document.getElementById("origin-row-errors");
      if (parsed.invalidLines.length > 0) {
        if (errorsEl) { errorsEl.textContent = parsed.invalidLines.join(" | "); errorsEl.hidden = false; }
        return;
      }
      if (errorsEl) { errorsEl.textContent = ""; errorsEl.hidden = true; }

      const kp = keyPathInput?.value.trim() || "~/.ssh/id_ed25519";
      const allowedOrigins = Object.keys(parsed.values);

      const resp = await safeSendMessage({
        type: "SET_CONFIG",
        keyPath: kp,
        allowedOrigins,
        originScopes: parsed.values
      });

      if (statusEl) {
        statusEl.hidden = false;
        if (resp.ok) {
          statusEl.textContent = "Setup complete!";
          statusEl.className = "status status-success";
          if (Object.keys(parsed.values).length > 0) markStepDone(3, "Configured");
          window.setTimeout(() => window.close(), 1000);
        } else {
          statusEl.textContent = `Error: ${resp.error || "Could not save config"}`;
          statusEl.className = "status status-error";
        }
      }
    });
  }
}

void init().catch((err) => {
  const statusEl = document.getElementById("status");
  if (statusEl) {
    statusEl.hidden = false;
    statusEl.textContent = `Error: ${err instanceof Error ? err.message : String(err)}`;
    statusEl.className = "status status-error";
  }
});
