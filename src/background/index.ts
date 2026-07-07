import { browser } from "@/shared/browser";
import type { RuntimeMessage, RuntimeResponse } from "@/shared/types";
import { evaluateSignPolicy, normalizeCompany, normalizeOrigin, normalizeNamespace } from "@/background/policy";
import type { OriginScope, OriginScopesMap } from "@/shared/types";
import { debugLog } from "@/shared/debug";

const ENABLED_KEY = "ssh_auth_enabled";
const NATIVE_HOST_KEY = "ssh_auth_native_host";
const ALLOWED_ORIGINS_KEY = "ssh_auth_allowed_origins";
const KEY_PATH_KEY = "ssh_auth_key_path";
const ORIGIN_SCOPES_KEY = "ssh_auth_origin_scopes";
const ORIGIN_NAMESPACES_KEY = "ssh_auth_origin_namespaces";
const ORIGIN_NAMESPACES_MIGRATED_KEY = "ssh_auth_origin_namespaces_migrated_v1";

const DEFAULT_NATIVE_HOST = "com.pubkey.auth";
const DEFAULT_ALLOWED_ORIGINS: string[] = [];
const DEFAULT_KEY_PATH = "~/.ssh/id_ed25519";
const LEGACY_DEFAULT_NAMESPACE = "default";

type NativeSignResponse = {
  ok?: boolean;
  signature?: string;
  error?: string;
};

function runtimeBrowserLabel(): string {
  const ua = navigator.userAgent;
  if (/Firefox\//i.test(ua)) return "firefox";
  if (/Edg\//i.test(ua)) return "edge";
  if (/Chrome\//i.test(ua)) return "chrome";
  if (/Safari\//i.test(ua) && !/Chrome\//i.test(ua)) return "safari";
  return "unknown";
}

async function getEnabled(): Promise<boolean> {
  const result = await browser.storage.local.get(ENABLED_KEY);
  return result[ENABLED_KEY] !== false;
}

async function setEnabled(enabled: boolean): Promise<void> {
  await browser.storage.local.set({ [ENABLED_KEY]: enabled });
}

async function getConfig(): Promise<{
  nativeHostName: string;
  allowedOrigins: string[];
  keyPath: string;
  originScopes: OriginScopesMap;
}> {
  const result = await browser.storage.local.get([
    NATIVE_HOST_KEY,
    ALLOWED_ORIGINS_KEY,
    KEY_PATH_KEY,
    ORIGIN_SCOPES_KEY,
    ORIGIN_NAMESPACES_KEY
  ]);
  const nativeHostName = String(result[NATIVE_HOST_KEY] || DEFAULT_NATIVE_HOST).trim() || DEFAULT_NATIVE_HOST;
  const rawOrigins: string[] = Array.isArray(result[ALLOWED_ORIGINS_KEY]) ? (result[ALLOWED_ORIGINS_KEY] as string[]) : DEFAULT_ALLOWED_ORIGINS;
  const allowedOrigins = rawOrigins
    .map((v) => normalizeOrigin(String(v || "").trim()))
    .filter((v): v is string => v.length > 0);

  const rawOriginScopes =
    result[ORIGIN_SCOPES_KEY] && typeof result[ORIGIN_SCOPES_KEY] === "object"
      ? (result[ORIGIN_SCOPES_KEY] as Record<string, unknown>)
      : {};
  const originScopes: OriginScopesMap = {};
  const addScope = (origin: string, scope: OriginScope): void => {
    if (!originScopes[origin]) {
      originScopes[origin] = [];
    }
    const exists = originScopes[origin].some((existing) => {
      return existing.namespace === scope.namespace && (existing.company || "") === (scope.company || "");
    });
    if (!exists) {
      originScopes[origin].push(scope);
    }
  };
  for (const [rawOrigin, rawScope] of Object.entries(rawOriginScopes)) {
    const origin = normalizeOrigin(String(rawOrigin || "").trim());
    if (!origin) continue;
    if (Array.isArray(rawScope)) {
      for (const item of rawScope) {
        if (!item || typeof item !== "object") continue;
        const namespace = normalizeNamespace(String((item as { namespace?: unknown }).namespace || "").trim());
        const company = normalizeCompany(String((item as { company?: unknown }).company || "").trim());
        if (!namespace) continue;
        addScope(origin, company ? { namespace, company } : { namespace });
      }
      continue;
    }
    if (typeof rawScope === "string") {
      const namespace = normalizeNamespace(rawScope);
      if (!namespace) continue;
      addScope(origin, { namespace });
      continue;
    }
    if (!rawScope || typeof rawScope !== "object") continue;
    const namespace = normalizeNamespace(String((rawScope as { namespace?: unknown }).namespace || "").trim());
    const company = normalizeCompany(String((rawScope as { company?: unknown }).company || "").trim());
    if (!namespace) continue;
    addScope(origin, company ? { namespace, company } : { namespace });
  }

  if (Object.keys(originScopes).length === 0) {
    const rawOriginNamespaces =
      result[ORIGIN_NAMESPACES_KEY] && typeof result[ORIGIN_NAMESPACES_KEY] === "object"
        ? (result[ORIGIN_NAMESPACES_KEY] as Record<string, unknown>)
        : {};
    for (const [rawOrigin, rawNamespace] of Object.entries(rawOriginNamespaces)) {
      const origin = normalizeOrigin(String(rawOrigin || "").trim());
      const namespace = normalizeNamespace(String(rawNamespace || "").trim());
      if (!origin || !namespace) continue;
      addScope(origin, { namespace });
    }
  }

  const keyPath = String(result[KEY_PATH_KEY] || DEFAULT_KEY_PATH).trim() || DEFAULT_KEY_PATH;
  return { nativeHostName, allowedOrigins: Array.from(new Set(allowedOrigins)), keyPath, originScopes };
}

async function setConfig(
  nativeHostName?: string,
  allowedOrigins?: string[],
  keyPath?: string,
  originScopes?: OriginScopesMap | Record<string, OriginScope>,
  originNamespaces?: Record<string, string>
): Promise<void> {
  const next: Record<string, unknown> = {};
  if (typeof nativeHostName === "string") {
    const v = nativeHostName.trim();
    next[NATIVE_HOST_KEY] = v || DEFAULT_NATIVE_HOST;
  }
  if (Array.isArray(allowedOrigins)) {
    const normalized = allowedOrigins
      .map((v) => normalizeOrigin(String(v || "").trim()))
      .filter((v): v is string => v.length > 0);
    next[ALLOWED_ORIGINS_KEY] = Array.from(new Set(normalized));
  }
  if (typeof keyPath === "string") {
    const v = keyPath.trim();
    next[KEY_PATH_KEY] = v || DEFAULT_KEY_PATH;
  }
  const normalizedScopes: OriginScopesMap = {};
  const addScope = (origin: string, scope: OriginScope): void => {
    if (!normalizedScopes[origin]) {
      normalizedScopes[origin] = [];
    }
    const exists = normalizedScopes[origin].some((existing) => {
      return existing.namespace === scope.namespace && (existing.company || "") === (scope.company || "");
    });
    if (!exists) {
      normalizedScopes[origin].push(scope);
    }
  };
  if (originScopes && typeof originScopes === "object") {
    for (const [rawOrigin, rawScope] of Object.entries(originScopes)) {
      const origin = normalizeOrigin(String(rawOrigin || "").trim());
      if (!origin || !rawScope) continue;
      if (Array.isArray(rawScope)) {
        for (const item of rawScope) {
          if (!item || typeof item !== "object") continue;
          const namespace = normalizeNamespace(String((item as { namespace?: unknown }).namespace || "").trim());
          const company = normalizeCompany(String((item as { company?: unknown }).company || "").trim());
          if (!namespace) continue;
          addScope(origin, company ? { namespace, company } : { namespace });
        }
        continue;
      }
      if (typeof rawScope !== "object") continue;
      const namespace = normalizeNamespace(String((rawScope as { namespace?: unknown }).namespace || "").trim());
      const company = normalizeCompany(String((rawScope as { company?: unknown }).company || "").trim());
      if (!namespace) continue;
      addScope(origin, company ? { namespace, company } : { namespace });
    }
  }
  if (Object.keys(normalizedScopes).length === 0 && originNamespaces && typeof originNamespaces === "object") {
    for (const [rawOrigin, rawNamespace] of Object.entries(originNamespaces)) {
      const origin = normalizeOrigin(String(rawOrigin || "").trim());
      const namespace = normalizeNamespace(String(rawNamespace || "").trim());
      if (!origin || !namespace) continue;
      addScope(origin, { namespace });
    }
  }
  if ((originScopes && typeof originScopes === "object") || (originNamespaces && typeof originNamespaces === "object")) {
    next[ORIGIN_SCOPES_KEY] = normalizedScopes;
  }

  if (Object.keys(next).length > 0) {
    await browser.storage.local.set(next);
  }
}

async function signChallengeWithNativeHost(
  nativeHostName: string,
  challenge: string,
  namespace: string,
  keyPath: string
): Promise<string> {
  const payload = {
    type: "SIGN_CHALLENGE",
    challenge,
    namespace,
    keyPath
  };
  const response = (await browser.runtime.sendNativeMessage(nativeHostName, payload)) as NativeSignResponse;
  if (!response) {
    throw new Error("No response from native host");
  }
  if (response.ok === false) {
    throw new Error(response.error || "Native host returned an error");
  }
  const signature = String(response.signature || "").trim();
  if (!signature) {
    throw new Error("Native host returned empty signature");
  }
  return signature;
}

browser.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install") {
    void browser.windows.create({
      url: browser.runtime.getURL("onboarding.html"),
      type: "popup",
      width: 700,
      height: 620
    });
  }

  const migrationState = await browser.storage.local.get([
    ALLOWED_ORIGINS_KEY,
    ORIGIN_SCOPES_KEY,
    ORIGIN_NAMESPACES_KEY,
    ORIGIN_NAMESPACES_MIGRATED_KEY
  ]);
  const migrated = migrationState[ORIGIN_NAMESPACES_MIGRATED_KEY] === true;
  const rawOrigins: string[] = Array.isArray(migrationState[ALLOWED_ORIGINS_KEY])
    ? (migrationState[ALLOWED_ORIGINS_KEY] as string[])
    : [];
  const normalizedOrigins = Array.from(
    new Set(
      rawOrigins
        .map((v) => normalizeOrigin(String(v || "").trim()))
        .filter((v): v is string => v.length > 0)
    )
  );
  const hasScopeMap =
    migrationState[ORIGIN_SCOPES_KEY] &&
    typeof migrationState[ORIGIN_SCOPES_KEY] === "object" &&
    Object.keys(migrationState[ORIGIN_SCOPES_KEY] as Record<string, unknown>).length > 0;
  const hasNamespaceMap =
    migrationState[ORIGIN_NAMESPACES_KEY] &&
    typeof migrationState[ORIGIN_NAMESPACES_KEY] === "object" &&
    Object.keys(migrationState[ORIGIN_NAMESPACES_KEY] as Record<string, unknown>).length > 0;

  if (!migrated) {
    if (!hasScopeMap && !hasNamespaceMap && normalizedOrigins.length > 0) {
      const migratedScopes: OriginScopesMap = {};
      for (const origin of normalizedOrigins) {
        migratedScopes[origin] = [{ namespace: LEGACY_DEFAULT_NAMESPACE }];
      }
      await browser.storage.local.set({
        [ORIGIN_SCOPES_KEY]: migratedScopes,
        [ORIGIN_NAMESPACES_MIGRATED_KEY]: true
      });
    } else {
      await browser.storage.local.set({ [ORIGIN_NAMESPACES_MIGRATED_KEY]: true });
    }
  }

  const cfg = await getConfig();
  await setConfig(cfg.nativeHostName, cfg.allowedOrigins, cfg.keyPath, cfg.originScopes);
});

browser.runtime.onMessage.addListener((rawMessage: unknown, sender: browser.Runtime.MessageSender) => {
  const message = rawMessage as RuntimeMessage;
  return (async (): Promise<RuntimeResponse> => {
    try {
      if (message.type === "PING") {
        return { ok: true, browser: runtimeBrowserLabel(), enabled: await getEnabled() };
      }
      if (message.type === "PING_NATIVE") {
        const cfg = await getConfig();
        try {
          await browser.runtime.sendNativeMessage(cfg.nativeHostName, { type: "PING" });
          return { ok: true, nativeHostConnected: true };
        } catch (err) {
          const detail = err instanceof Error ? err.message : String(err);
          debugLog("background", "native host ping failed", detail);
          return { ok: true, nativeHostConnected: false, error: detail };
        }
      }
      if (message.type === "GET_STATUS") {
        const cfg = await getConfig();
        return {
          ok: true,
          browser: runtimeBrowserLabel(),
          enabled: await getEnabled(),
          nativeHostName: cfg.nativeHostName,
          allowedOrigins: cfg.allowedOrigins,
          keyPath: cfg.keyPath,
          originScopes: cfg.originScopes
        };
      }
      if (message.type === "SET_ENABLED") {
        await setEnabled(message.enabled);
        return { ok: true, browser: runtimeBrowserLabel(), enabled: await getEnabled() };
      }
      if (message.type === "GET_CONFIG") {
        const cfg = await getConfig();
        return {
          ok: true,
          nativeHostName: cfg.nativeHostName,
          allowedOrigins: cfg.allowedOrigins,
          keyPath: cfg.keyPath,
          originScopes: cfg.originScopes
        };
      }
      if (message.type === "SET_CONFIG") {
        await setConfig(
          message.nativeHostName,
          message.allowedOrigins,
          message.keyPath,
          message.originScopes,
          message.originNamespaces
        );
        const cfg = await getConfig();
        return {
          ok: true,
          nativeHostName: cfg.nativeHostName,
          allowedOrigins: cfg.allowedOrigins,
          keyPath: cfg.keyPath,
          originScopes: cfg.originScopes
        };
      }
      if (message.type === "VALIDATE_KEY") {
        const cfg = await getConfig();
        try {
          const resp = await browser.runtime.sendNativeMessage(cfg.nativeHostName, {
            type: "VALIDATE_KEY",
            keyPath: cfg.keyPath
          }) as { ok?: boolean; error?: string };
          if (resp && resp.ok === false) {
            return { ok: true, keyValid: false, keyError: resp.error || "Key validation failed" };
          }
          return { ok: true, keyValid: true };
        } catch (err) {
          const detail = err instanceof Error ? err.message : String(err);
          return { ok: true, keyValid: false, keyError: detail };
        }
      }
      if (message.type === "SIGN_CHALLENGE") {
        const senderOrigin = sender.url ? new URL(sender.url).origin : "";
        if (!senderOrigin) {
          return { ok: false, error: "Cannot determine sender origin" };
        }
        const enabled = await getEnabled();
        const cfg = await getConfig();
        const policy = evaluateSignPolicy({
          enabled,
          challenge: message.challenge,
          namespace: message.namespace,
          company: message.company,
          origin: senderOrigin,
          allowedOrigins: cfg.allowedOrigins,
          originScopes: cfg.originScopes
        });
        if (!policy.ok) {
          debugLog("background", "policy rejected signing", policy.error);
          return { ok: false, error: policy.error };
        }

        debugLog("background", "signing challenge", { origin: policy.origin, namespace: policy.expectedNamespace });
        const signature = await signChallengeWithNativeHost(
          cfg.nativeHostName,
          policy.challenge,
          policy.expectedNamespace,
          cfg.keyPath
        );
        return { ok: true, signature };
      }
      return { ok: false, error: "Unsupported message" };
    } catch (error) {
      return { ok: false, error: error instanceof Error ? error.message : String(error) };
    }
  })();
});
