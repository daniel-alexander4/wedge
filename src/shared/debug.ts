declare const __DEBUG__: boolean | undefined;

const DEBUG = typeof __DEBUG__ === "boolean" ? __DEBUG__ : false;

export function debugLog(scope: string, ...args: unknown[]): void {
  if (!DEBUG) return;
  console.log(`[sshkey-web-auth:${scope}]`, ...args);
}
