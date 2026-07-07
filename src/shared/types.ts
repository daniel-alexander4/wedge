export type OriginScope = {
  namespace: string;
  company?: string;
};

export type OriginScopesMap = Record<string, OriginScope[]>;

export type RuntimeMessage =
  | { type: "PING" }
  | { type: "GET_STATUS" }
  | { type: "SET_ENABLED"; enabled: boolean }
  | { type: "GET_CONFIG" }
  | {
      type: "SET_CONFIG";
      nativeHostName?: string;
      allowedOrigins?: string[];
      keyPath?: string;
      originScopes?: OriginScopesMap | Record<string, OriginScope>;
      originNamespaces?: Record<string, string>;
    }
  | { type: "SIGN_CHALLENGE"; challenge: string; namespace: string; company?: string; origin: string }
  | { type: "PING_NATIVE" }
  | { type: "VALIDATE_KEY" };

export type RuntimeResponse = {
  ok: boolean;
  browser?: string;
  enabled?: boolean;
  nativeHostConnected?: boolean;
  nativeHostName?: string;
  allowedOrigins?: string[];
  originScopes?: OriginScopesMap;
  keyPath?: string;
  signature?: string;
  keyValid?: boolean;
  keyError?: string;
  error?: string;
};
