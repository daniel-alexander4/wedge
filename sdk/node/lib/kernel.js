// Signature-verification kernel.
//
// Shells out to `ssh-keygen -Y verify` (OpenSSH 8.1+), so wedge-rp implements
// no cryptography of its own — verification behaves exactly like sshd's
// allowed_signers handling. Only public keys and signatures pass through here;
// private keys never leave the user's ssh-agent.
//
// Port of sdk/python/wedge_rp/kernel.py — keep the validation rules in lockstep.

import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

// The principal is the first token of an allowed_signers line, so it must be a
// single inert token: no whitespace, and none of the characters ssh-keygen
// treats as comments, quoting, or patterns ("#", '"', "*", "?", ",").
export const PRINCIPAL_RE = /^[A-Za-z0-9._@+=-]{1,256}$/;

const KEYTYPE_RE = /^[A-Za-z0-9@.-]{1,64}$/;
const KEYDATA_RE = /^[A-Za-z0-9+/=]{1,16384}$/;
const SIG_HEADER = '-----BEGIN SSH SIGNATURE-----';
const MAX_SIGNATURE_BYTES = 64 * 1024;

// ssh-keygen is missing or too old for `-Y verify` (needs OpenSSH 8.1+).
export class SSHKeygenUnavailable extends Error {}

// Returns [keytype, base64data] from an OpenSSH public-key line, dropping any
// trailing comment; null if the line doesn't look like a public key.
export function splitPublicKey(publicKey) {
  const fields = String(publicKey ?? '').trim().split(/\s+/);
  if (fields.length < 2) return null;
  const [keytype, keydata] = fields;
  if (!KEYTYPE_RE.test(keytype) || !KEYDATA_RE.test(keydata)) return null;
  return [keytype, keydata];
}

// Whether two public-key lines denote the same key (type + data; comments and
// surrounding whitespace ignored).
export function sameKey(a, b) {
  const pa = splitPublicKey(a);
  const pb = splitPublicKey(b);
  return pa !== null && pb !== null && pa[0] === pb[0] && pa[1] === pb[1];
}

// Verify an armored SSHSIG `signature` over the exact bytes of `challenge`,
// made with `namespace`, against `publicKey`.
//
// Resolves { ok, detail }. Malformed inputs and failed verification resolve
// { ok: false, detail }; a missing or pre-8.1 ssh-keygen rejects with
// SSHKeygenUnavailable (server misconfiguration, not a bad login).
export async function verifySignature(challenge, signature, { principal, publicKey, namespace, timeout = 10000 }) {
  if (!PRINCIPAL_RE.test(principal ?? '')) {
    return { ok: false, detail: 'invalid principal' };
  }
  const key = splitPublicKey(publicKey ?? '');
  if (key === null) {
    return { ok: false, detail: 'malformed public key' };
  }
  if (
    typeof signature !== 'string'
    || !signature.trimStart().startsWith(SIG_HEADER)
    || signature.length > MAX_SIGNATURE_BYTES
  ) {
    return { ok: false, detail: 'malformed signature' };
  }
  if (!namespace || namespace.includes('\n') || namespace.includes('\x00')) {
    return { ok: false, detail: 'invalid namespace' };
  }

  const dir = await mkdtemp(join(tmpdir(), 'wedge-rp-'));
  try {
    const allowed = join(dir, 'allowed_signers');
    const sigfile = join(dir, 'challenge.sig');
    await writeFile(allowed, `${principal} ${key[0]} ${key[1]}\n`, 'utf8');
    await writeFile(sigfile, signature.trim() + '\n', 'utf8');

    const pending = execFileAsync(
      'ssh-keygen',
      ['-Y', 'verify', '-f', allowed, '-I', principal, '-n', namespace, '-s', sigfile],
      { timeout, maxBuffer: 1024 * 1024 },
    );
    // The child can exit before stdin is written (bad args) — don't crash on EPIPE.
    pending.child.stdin.on('error', () => {});
    pending.child.stdin.end(challenge, 'utf8');

    try {
      const { stdout } = await pending;
      return { ok: true, detail: stdout.trim() || 'signature verified' };
    } catch (err) {
      if (err.code === 'ENOENT') {
        throw new SSHKeygenUnavailable('ssh-keygen not found — install openssh-client');
      }
      if (err.killed) {
        return { ok: false, detail: 'verification timed out' };
      }
      const stderr = (err.stderr ?? '').trim();
      if (stderr.includes('unknown option') || stderr.toLowerCase().startsWith('usage:')) {
        throw new SSHKeygenUnavailable('ssh-keygen lacks -Y verify — OpenSSH 8.1+ required');
      }
      return { ok: false, detail: stderr || (err.stdout ?? '').trim() || 'signature verification failed' };
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
