// Type declarations for wedge-rp. Hand-written; the source of truth is the
// JS in lib/ (this package ships no build step).

export declare const DISCOVERY_PATH: '/.well-known/wedge.json';
export declare const START_PATH: '/wedge/start';
export declare const CHALLENGE_PATH: '/wedge/challenge';
export declare const VERIFY_PATH: '/wedge/verify';
export declare const STATUS_PATH: '/wedge/status';
export declare const APP_START_PATH: '/wedge/app-start';
export declare const CLAIM_PATH: '/wedge/claim';
export declare const SCRIPT_PATH: '/wedge/wedge.js';
export declare const BINDING_COOKIE: 'wedge_flow';
export declare const CHALLENGE_RE: RegExp;
export declare const REQUEST_ID_RE: RegExp;
export declare const DEFAULT_CHALLENGE_TTL: number;

export declare class SSHKeygenUnavailable extends Error {}

export declare function splitPublicKey(publicKey: string): [keytype: string, keydata: string] | null;
export declare function sameKey(a: string, b: string): boolean;
export declare function verifySignature(
  challenge: string,
  signature: string,
  options: { principal: string; publicKey: string; namespace: string; timeout?: number },
): Promise<{ ok: boolean; detail: string }>;

export declare function normalizeOrigin(value: string): string;
export declare function equivalentOrigins(origin: string): string[];

export interface RequestRecord {
  requestId: string;
  challenge: string;
  namespace: string;
  username: string | null;
  browserNonce: string | null;
  claimToken: string | null;
  status: 'pending' | 'authenticated' | 'denied';
  authenticatedUsername: string | null;
  expiresAt: number;
}

export interface RequestStore {
  put(record: RequestRecord): void;
  get(requestId: string): RequestRecord | null;
  setAuthenticated(requestId: string, username: string): boolean;
  takeAuthenticated(requestId: string): RequestRecord | null;
}

export declare class MemoryStore implements RequestStore {
  put(record: RequestRecord): void;
  get(requestId: string): RequestRecord | null;
  setAuthenticated(requestId: string, username: string): boolean;
  takeAuthenticated(requestId: string): RequestRecord | null;
}

export declare class SqliteStore implements RequestStore {
  constructor(path: string);
  put(record: RequestRecord): void;
  get(requestId: string): RequestRecord | null;
  setAuthenticated(requestId: string, username: string): boolean;
  takeAuthenticated(requestId: string): RequestRecord | null;
}

export type MaybePromise<T> = T | Promise<T>;

export interface WedgeRPOptions {
  origin: string;
  findKeys?: ((username: string) => MaybePromise<string | string[] | null | undefined>) | null;
  findUserByPublicKey?: ((publicKey: string) => MaybePromise<[string, string | string[]] | null | undefined>) | null;
  store?: RequestStore | null;
  challengeTtl?: number;
  verifyTimeout?: number;
  maxConcurrentVerifies?: number;
  verifyRateLimit?: [attempts: number, windowSeconds: number] | null;
}

export interface HandlerResult {
  status: number;
  body: Record<string, unknown>;
}

export declare class WedgeRP {
  constructor(options: WedgeRPOptions);
  readonly origin: string;
  readonly challengeTtl: number;
  get usesHttps(): boolean;
  isSameOrigin(value: string | null | undefined): boolean;
  signLink(requestId: string): string;
  discovery(): { version: 1; namespace: string; challenge_url: string; verify_url: string };
  start(username?: string | null): HandlerResult & { browserNonce: string | null };
  challenge(requestId: string): HandlerResult;
  appStart(): HandlerResult;
  verify(body: unknown, options?: { source?: string | null }): Promise<HandlerResult>;
  status(requestId: string, browserNonce: string | null | undefined): {
    body: { status: 'pending' | 'authenticated' | 'denied' | 'expired' };
    username: string | null;
  };
  claim(requestId: string, claimToken: string | null | undefined): string | null;
}
