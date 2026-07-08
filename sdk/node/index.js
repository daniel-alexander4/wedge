// wedge-rp — relying-party middleware for wedge (SSH-key web authentication).
//
// Add "Sign in with wedge" to a Node web app: create a WedgeRP with your
// site's origin and account-lookup callbacks, then mount it — via the Express
// router (import { wedgeRouter } from 'wedge-rp/express') or your own thin
// routing over the framework-neutral handlers. Wire spec: docs/wedge-spec-v1.md
// in the wedge repository.

export {
  WedgeRP,
  normalizeOrigin,
  equivalentOrigins,
  DISCOVERY_PATH,
  START_PATH,
  CHALLENGE_PATH,
  VERIFY_PATH,
  STATUS_PATH,
  APP_START_PATH,
  CLAIM_PATH,
  SCRIPT_PATH,
  BINDING_COOKIE,
  CHALLENGE_RE,
  REQUEST_ID_RE,
  DEFAULT_CHALLENGE_TTL,
} from './lib/core.js';
export { verifySignature, sameKey, splitPublicKey, SSHKeygenUnavailable } from './lib/kernel.js';
export { MemoryStore, SqliteStore } from './lib/store.js';
