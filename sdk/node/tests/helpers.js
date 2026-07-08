// Shared test fixtures: a real throwaway SSH key and real SSHSIG signatures.
//
// The tests exercise the actual ssh-keygen binary end to end — no mocked
// crypto — so a passing suite means the kernel interoperates with OpenSSH.

import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const HAVE_SSH_KEYGEN = spawnSync('ssh-keygen', ['-Y', 'help']).error?.code !== 'ENOENT';

// A passphrase-less ed25519 keypair in a temp dir, able to sign.
export class KeyPair {
  constructor(comment = 'wedge-rp-test') {
    this.dir = mkdtempSync(join(tmpdir(), 'wedge-rp-test-'));
    this.keyPath = join(this.dir, 'key');
    execFileSync('ssh-keygen', ['-t', 'ed25519', '-N', '', '-C', comment, '-q', '-f', this.keyPath]);
    this.publicKey = readFileSync(`${this.keyPath}.pub`, 'utf8').trim();
  }

  // Armored SSHSIG over the challenge bytes, like the wedge app makes.
  sign(challenge, namespace) {
    return execFileSync('ssh-keygen', ['-Y', 'sign', '-f', this.keyPath, '-n', namespace], {
      input: challenge,
    }).toString();
  }

  close() {
    rmSync(this.dir, { recursive: true, force: true });
  }
}
