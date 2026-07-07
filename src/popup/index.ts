import { browser } from "@/shared/browser";
import type { OriginScope, OriginScopesMap, RuntimeResponse } from "@/shared/types";
import { debugLog } from "@/shared/debug";
import { RUNTIME_MESSAGE_TIMEOUT_MS } from "@/shared/timeouts";

let toggleBtn: HTMLButtonElement | null = null;
let statusEl: HTMLDivElement | null = null;
let keyPathInput: HTMLInputElement | null = null;
let keyTypeTabs: HTMLButtonElement[] = [];
let saveBtn: HTMLButtonElement | null = null;
let verifyBtn: HTMLButtonElement | null = null;
let nativeHelpBox: HTMLDivElement | null = null;
let nativeStatusLine: HTMLDivElement | null = null;
let helpDetails: HTMLDivElement | null = null;
let extIdEl: HTMLElement | null = null;
let installCmdEl: HTMLPreElement | null = null;
let copyCmdBtn: HTMLButtonElement | null = null;
let noOriginsWarning: HTMLDivElement | null = null;
let originRowsContainer: HTMLDivElement | null = null;
let addOriginRowBtn: HTMLButtonElement | null = null;
let originRowErrors: HTMLDivElement | null = null;
let checklistEl: HTMLDivElement | null = null;

const KEY_PATHS = {
  ed25519: "~/.ssh/id_ed25519",
  rsa: "~/.ssh/id_rsa",
  ecdsa: "~/.ssh/id_ecdsa"
} as const;

type KeyType = keyof typeof KEY_PATHS;
const NAMESPACE_REGEX = /^[A-Za-z0-9._:-]{1,64}$/;
const MAX_ORIGIN_ROWS = 100;

function setStatus(text: string, level?: "success" | "error"): void {
  if (!statusEl) return;
  statusEl.textContent = text;
  statusEl.classList.remove("status-success", "status-error");
  if (level) statusEl.classList.add(`status-${level}`);
  statusEl.hidden = !text;
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

function bindDomElements(): void {
  toggleBtn = document.getElementById("toggle-enabled") as HTMLButtonElement | null;
  statusEl = document.getElementById("status") as HTMLDivElement | null;
  keyPathInput = document.getElementById("key-path") as HTMLInputElement | null;
  keyTypeTabs = Array.from(document.querySelectorAll("[data-key-type]")) as HTMLButtonElement[];
  saveBtn = document.getElementById("save-config") as HTMLButtonElement | null;
  verifyBtn = document.getElementById("verify-setup") as HTMLButtonElement | null;
  nativeHelpBox = document.getElementById("native-help") as HTMLDivElement | null;
  nativeStatusLine = document.getElementById("native-status-line") as HTMLDivElement | null;
  helpDetails = document.getElementById("help-details") as HTMLDivElement | null;
  extIdEl = document.getElementById("ext-id") as HTMLElement | null;
  installCmdEl = document.getElementById("install-cmd") as HTMLPreElement | null;
  copyCmdBtn = document.getElementById("copy-cmd") as HTMLButtonElement | null;
  noOriginsWarning = document.getElementById("no-origins-warning") as HTMLDivElement | null;
  originRowsContainer = document.getElementById("origin-rows") as HTMLDivElement | null;
  addOriginRowBtn = document.getElementById("add-origin-row") as HTMLButtonElement | null;
  originRowErrors = document.getElementById("origin-row-errors") as HTMLDivElement | null;
  checklistEl = document.getElementById("setup-checklist") as HTMLDivElement | null;
}

async function waitForDomReady(): Promise<void> {
  if (document.readyState !== "loading") return;
  await new Promise<void>((resolve) => {
    document.addEventListener("DOMContentLoaded", () => resolve(), { once: true });
  });
}

async function safeSendMessage(message: unknown, timeoutMs = RUNTIME_MESSAGE_TIMEOUT_MS): Promise<RuntimeResponse> {
  let timeoutId: number | null = null;
  const timeoutPromise = new Promise<RuntimeResponse>((resolve) => {
    timeoutId = window.setTimeout(() => {
      resolve({ ok: false, error: "Extension message timed out" });
    }, timeoutMs);
  });
  const messagePromise = (browser.runtime.sendMessage(message) as Promise<RuntimeResponse>).catch((error: unknown) => ({
    ok: false,
    error: error instanceof Error ? error.message : String(error)
  }));
  const response = (await Promise.race([messagePromise, timeoutPromise])) as RuntimeResponse;
  if (timeoutId !== null) {
    window.clearTimeout(timeoutId);
  }
  debugLog("popup", "runtime message result", { ok: response.ok, error: response.error || null });
  return response;
}

function renderToggle(enabled: boolean): void {
  if (!toggleBtn) return;
  toggleBtn.setAttribute("aria-pressed", enabled ? "true" : "false");
  toggleBtn.textContent = enabled ? "On" : "Off";
}

function detectKeyType(keyPath: string): KeyType | null {
  const value = keyPath.trim();
  if (value.endsWith("id_ed25519")) return "ed25519";
  if (value.endsWith("id_rsa")) return "rsa";
  if (value.endsWith("id_ecdsa")) return "ecdsa";
  return null;
}

function renderKeyTypeTabs(active: KeyType | null): void {
  for (const tab of keyTypeTabs) {
    const tabType = (tab.dataset.keyType || "") as KeyType;
    tab.setAttribute("aria-pressed", tabType === active ? "true" : "false");
  }
}

// ---------------------------------------------------------------------------
// Target system rows
// ---------------------------------------------------------------------------

function splitOriginParts(origin: string): { host: string; port: string } {
  try {
    const url = new URL(origin);
    const port = url.port || "";
    const host = port ? origin.replace(`:${port}`, "") : origin;
    return { host, port };
  } catch {
    return { host: origin, port: "" };
  }
}

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
  removeBtn.addEventListener("click", () => {
    row.remove();
  });

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

  // Validate origin (host)
  const rawOrigin = originInput.value.trim();
  if (rawOrigin) {
    try {
      new URL(rawOrigin);
      originInput.classList.remove("invalid");
    } catch {
      originInput.classList.add("invalid");
      valid = false;
    }
  } else {
    originInput.classList.remove("invalid");
  }

  // Validate port
  const portVal = portInput.value.trim();
  if (portVal) {
    const portNum = Number(portVal);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      portInput.classList.add("invalid");
      valid = false;
    } else {
      portInput.classList.remove("invalid");
    }
  } else {
    portInput.classList.remove("invalid");
  }

  // Validate namespace
  const nsVal = nsInput.value.trim();
  if (nsVal && !NAMESPACE_REGEX.test(nsVal)) {
    nsInput.classList.add("invalid");
    valid = false;
  } else {
    nsInput.classList.remove("invalid");
  }

  return valid;
}

function collectOriginScopes(): { values: OriginScopesMap; invalidLines: string[] } {
  const out: OriginScopesMap = {};
  const invalidLines: string[] = [];
  if (!originRowsContainer) return { values: out, invalidLines };

  const rows = originRowsContainer.querySelectorAll(".origin-row");
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

    if (!rawHost && !nsVal && !rawPort) continue; // skip empty rows

    if (!rawHost || !nsVal) {
      invalidLines.push(`${rawHost || "(empty host)"} — host and namespace are required`);
      continue;
    }

    // Validate port if provided
    if (rawPort) {
      const portNum = Number(rawPort);
      if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
        invalidLines.push(`${rawHost} — invalid port "${rawPort}"`);
        continue;
      }
    }

    // Build the full origin URL with optional port
    const fullUrl = rawPort ? `${rawHost}:${rawPort}` : rawHost;
    let origin = "";
    try {
      origin = new URL(fullUrl).origin;
    } catch {
      invalidLines.push(`${fullUrl} — invalid URL`);
      continue;
    }

    if (!NAMESPACE_REGEX.test(nsVal)) {
      invalidLines.push(`${rawHost} — invalid namespace "${nsVal}"`);
      continue;
    }

    if (!out[origin]) out[origin] = [];
    const candidate: OriginScope = { namespace: nsVal };
    const exists = out[origin].some(
      (existing) => existing.namespace === candidate.namespace
    );
    if (!exists) out[origin].push(candidate);
  }

  return { values: out, invalidLines };
}

function renderOriginRows(scopes: OriginScopesMap): void {
  if (!originRowsContainer) return;
  originRowsContainer.innerHTML = "";

  const entries = Object.entries(scopes).sort(([a], [b]) => a.localeCompare(b));
  for (const [origin, scopeList] of entries) {
    const { host, port } = splitOriginParts(origin);
    for (const scope of Array.isArray(scopeList) ? scopeList : []) {
      const row = createOriginRow(host, scope.namespace, port);
      originRowsContainer.appendChild(row);
    }
  }

  // Always have at least one empty row
  if (originRowsContainer.children.length === 0) {
    originRowsContainer.appendChild(createOriginRow());
  }
}

function updateNoOriginsWarning(): void {
  if (!noOriginsWarning || !originRowsContainer) return;
  const rows = originRowsContainer.querySelectorAll(".origin-row");
  let hasData = false;
  for (const row of rows) {
    const originInput = row.querySelector(".origin-input") as HTMLInputElement | null;
    const nsInput = row.querySelector(".namespace-input") as HTMLInputElement | null;
    if (originInput?.value.trim() && nsInput?.value.trim()) {
      hasData = true;
      break;
    }
  }
  noOriginsWarning.hidden = hasData;
}

// ---------------------------------------------------------------------------
// Checklist
// ---------------------------------------------------------------------------

function setCheckItem(id: string, status: "pass" | "fail" | "pending", label: string): void {
  const iconEl = document.getElementById(`${id}-icon`);
  const labelEl = document.getElementById(`${id}-label`);
  if (iconEl) {
    iconEl.className = `check-icon ${status}`;
    iconEl.textContent = status === "pass" ? "\u2713" : status === "fail" ? "\u2717" : "\u2022";
  }
  if (labelEl) labelEl.textContent = label;
}

// ---------------------------------------------------------------------------
// Native host / verify
// ---------------------------------------------------------------------------

async function checkNativeHost(): Promise<boolean> {
  if (!nativeHelpBox) return false;
  const response = await safeSendMessage({ type: "PING_NATIVE" });
  const connected = response.ok && response.nativeHostConnected === true;
  // Only show the help box when not connected (install instructions)
  nativeHelpBox.hidden = connected;
  nativeHelpBox.classList.remove("connected", "disconnected");
  nativeHelpBox.classList.add(connected ? "connected" : "disconnected");
  if (nativeStatusLine) {
    if (connected) {
      nativeStatusLine.textContent = "Native host connected";
    } else {
      const reason = response.error ? ` \u2014 ${response.error}` : "";
      nativeStatusLine.textContent = `Native host not connected${reason}`;
    }
  }
  if (helpDetails) {
    helpDetails.hidden = connected;
  }
  if (!connected) {
    const extId = browser.runtime.id || "";
    if (extIdEl) extIdEl.textContent = extId;
    const cmd = getInstallCommand(extId);
    if (installCmdEl) installCmdEl.textContent = cmd;
  }
  return connected;
}

async function verifySetup(): Promise<void> {
  if (checklistEl) checklistEl.hidden = false;

  setCheckItem("check-native", "pending", "Checking native host...");
  setCheckItem("check-key", "pending", "Checking SSH key...");
  setCheckItem("check-origins", "pending", "Checking target systems...");

  // Check native host
  const nativeConnected = await checkNativeHost();
  setCheckItem(
    "check-native",
    nativeConnected ? "pass" : "fail",
    nativeConnected ? "Native host connected" : "Native host not connected"
  );

  // Check SSH key via native host
  if (nativeConnected) {
    const keyResp = await safeSendMessage({ type: "VALIDATE_KEY" });
    const keyOk = keyResp.ok && keyResp.keyValid === true;
    setCheckItem(
      "check-key",
      keyOk ? "pass" : "fail",
      keyOk ? "SSH key valid" : `SSH key: ${keyResp.keyError || "validation failed"}`
    );
  } else {
    setCheckItem("check-key", "fail", "SSH key: cannot check without native host");
  }

  // Check target systems
  const collected = collectOriginScopes();
  const hasOrigins = Object.keys(collected.values).length > 0;
  setCheckItem(
    "check-origins",
    hasOrigins ? "pass" : "fail",
    hasOrigins ? `${Object.keys(collected.values).length} target system(s) configured` : "No target systems configured"
  );
  updateNoOriginsWarning();

  // Collapse after 4 seconds
  window.setTimeout(() => {
    if (checklistEl) checklistEl.hidden = true;
    if (nativeHelpBox) nativeHelpBox.hidden = true;
    if (noOriginsWarning) noOriginsWarning.hidden = true;
  }, 4000);
}

// ---------------------------------------------------------------------------
// Config load/save
// ---------------------------------------------------------------------------

function renderConfig(response: RuntimeResponse): void {
  if (!response.ok) {
    setStatus(`Error: ${response.error || "Unknown error"}`, "error");
    return;
  }
  renderToggle(Boolean(response.enabled));
  if (keyPathInput) {
    const keyPath = String(response.keyPath || "");
    keyPathInput.value = keyPath;
    renderKeyTypeTabs(detectKeyType(keyPath));
  }
  renderOriginRows(response.originScopes || {});
}

async function refresh(): Promise<void> {
  setStatus("");
  const response = await safeSendMessage({ type: "GET_STATUS" });
  renderConfig(response);
}

async function saveConfig(): Promise<void> {
  const keyPath = String(keyPathInput?.value || "").trim();
  const parsedScopes = collectOriginScopes();

  if (originRowErrors) {
    if (parsedScopes.invalidLines.length > 0) {
      originRowErrors.textContent = parsedScopes.invalidLines.join(" | ");
      originRowErrors.hidden = false;
    } else {
      originRowErrors.textContent = "";
      originRowErrors.hidden = true;
    }
  }

  if (parsedScopes.invalidLines.length > 0) {
    setStatus(`Error: invalid target system(s)`, "error");
    return;
  }

  const allowedOrigins = Object.keys(parsedScopes.values);
  const response = await safeSendMessage({
    type: "SET_CONFIG",
    keyPath,
    allowedOrigins,
    originScopes: parsedScopes.values
  });

  if (!response.ok) {
    setStatus(`Error: ${response.error || "Could not save config"}`, "error");
    return;
  }
  await refresh();
  setStatus("Config saved.", "success");

  // Close popup after a visible delay so user can read the confirmation
  if (window.location.pathname.endsWith("/popup.html") || window.location.pathname.endsWith("popup.html")) {
    window.setTimeout(() => {
      window.close();
    }, 1200);
  }
}

async function initPopup(): Promise<void> {
  await waitForDomReady();
  bindDomElements();

  if (toggleBtn) {
    const btn = toggleBtn;
    btn.addEventListener("click", async () => {
      const currentlyEnabled = btn.getAttribute("aria-pressed") === "true";
      const response = await safeSendMessage({
        type: "SET_ENABLED",
        enabled: !currentlyEnabled
      });
      renderConfig(response);
    });
  }

  if (saveBtn) {
    saveBtn.addEventListener("click", () => {
      void saveConfig();
    });
  }

  if (verifyBtn) {
    verifyBtn.addEventListener("click", () => {
      void verifySetup();
    });
  }

  if (copyCmdBtn && installCmdEl) {
    const cmdEl = installCmdEl;
    const btn = copyCmdBtn;
    btn.addEventListener("click", () => {
      void navigator.clipboard.writeText(cmdEl.textContent || "").then(() => {
        btn.textContent = "Copied!";
        window.setTimeout(() => { btn.textContent = "Copy"; }, 1500);
      });
    });
  }

  if (addOriginRowBtn && originRowsContainer) {
    const container = originRowsContainer;
    addOriginRowBtn.addEventListener("click", () => {
      container.appendChild(createOriginRow());
    });
  }

  for (const tab of keyTypeTabs) {
    tab.addEventListener("click", () => {
      const type = String(tab.dataset.keyType || "") as KeyType;
      const nextPath = KEY_PATHS[type];
      if (!nextPath || !keyPathInput) return;
      keyPathInput.value = nextPath;
      renderKeyTypeTabs(type);
    });
  }

  void refresh();
}

void initPopup().catch((error) => {
  setStatus(`Error: ${error instanceof Error ? error.message : String(error)}`, "error");
});
