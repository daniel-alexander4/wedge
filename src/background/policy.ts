import type { OriginScope } from "@/shared/types";

const CHALLENGE_REGEX = /^[A-Za-z0-9_-]{16,256}$/;
const NAMESPACE_REGEX = /^[A-Za-z0-9._:-]{1,64}$/;
const COMPANY_REGEX = /^[A-Za-z0-9._:-]{1,64}$/;

type SignPolicyInput = {
  enabled: boolean;
  challenge: string;
  namespace: string;
  company?: string;
  origin: string;
  allowedOrigins: string[];
  originScopes: Record<string, OriginScope[]>;
};

type SignPolicyResult =
  | { ok: true; origin: string; expectedNamespace: string; expectedCompany?: string; challenge: string }
  | { ok: false; error: string };

export function normalizeOrigin(value: string): string {
  try {
    return new URL(value).origin;
  } catch {
    return "";
  }
}

export function normalizeNamespace(value: string): string {
  const v = String(value || "").trim();
  return NAMESPACE_REGEX.test(v) ? v : "";
}

export function normalizeCompany(value: string): string {
  const v = String(value || "").trim();
  return COMPANY_REGEX.test(v) ? v : "";
}

function validateChallenge(challenge: string): string | null {
  if (!CHALLENGE_REGEX.test(challenge)) {
    return "Invalid challenge format";
  }
  return null;
}

function equivalentOrigins(origin: string): string[] {
  const values = new Set<string>([origin]);
  try {
    const u = new URL(origin);
    if (u.hostname === "localhost") {
      u.hostname = "127.0.0.1";
      values.add(u.origin);
    } else if (u.hostname === "127.0.0.1") {
      u.hostname = "localhost";
      values.add(u.origin);
    }
  } catch {
    // noop
  }
  return Array.from(values);
}

export function evaluateSignPolicy(input: SignPolicyInput): SignPolicyResult {
  if (!input.enabled) {
    return { ok: false, error: "Extension disabled" };
  }

  const challenge = String(input.challenge || "").trim();
  const namespace = String(input.namespace || "").trim();
  const company = String(input.company || "").trim();
  const origin = normalizeOrigin(String(input.origin || "").trim());
  if (!challenge || !namespace || !origin) {
    return { ok: false, error: "Missing challenge, namespace, or origin" };
  }

  const validationError = validateChallenge(challenge);
  if (validationError) {
    return { ok: false, error: validationError };
  }

  if (!normalizeNamespace(namespace)) {
    return { ok: false, error: "Invalid namespace format" };
  }
  if (company && !normalizeCompany(company)) {
    return { ok: false, error: "Invalid company format" };
  }

  const matchedOrigin = equivalentOrigins(origin).find((candidate) => input.allowedOrigins.includes(candidate));
  if (!matchedOrigin) {
    return { ok: false, error: `Origin not allowed: ${origin}` };
  }

  const scopeOrigin = equivalentOrigins(origin).find((candidate) => Array.isArray(input.originScopes[candidate]));
  const expectedScopes = scopeOrigin ? input.originScopes[scopeOrigin] : [];
  if (expectedScopes.length === 0) {
    return { ok: false, error: `No namespace configured for origin: ${origin}` };
  }
  const namespaceMatches = expectedScopes.filter((scope) => String(scope.namespace || "").trim() === namespace);
  if (namespaceMatches.length === 0) {
    const configuredNamespaces = Array.from(
      new Set(
        expectedScopes
          .map((scope) => String(scope.namespace || "").trim())
          .filter((v) => v.length > 0)
      )
    );
    const expectedNamespace = configuredNamespaces[0] || "<none>";
    return {
      ok: false,
      error: `ERROR\nExtension Namespace: ${expectedNamespace}\nReceived Namespace: ${namespace || "<empty>"}`
    };
  }
  const matchingScope = namespaceMatches.find((scope) => {
    const expectedCompany = String(scope.company || "").trim();
    if (!expectedCompany) return true;
    return company === expectedCompany;
  });
  if (!matchingScope) {
    const expectedCompany = String(namespaceMatches[0]?.company || "").trim();
    if (!company) {
      return {
        ok: false,
        error: `ERROR\nExtension Company: ${expectedCompany}\nReceived Company: <empty>`
      };
    }
    return {
      ok: false,
      error: `ERROR\nExtension Company: ${expectedCompany}\nReceived Company: ${company}`
    };
  }
  const expectedNamespace = String(matchingScope.namespace || "").trim();
  const expectedCompany = String(matchingScope.company || "").trim();

  return { ok: true, origin, expectedNamespace, expectedCompany: expectedCompany || undefined, challenge };
}
