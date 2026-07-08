"""Shared test fixtures: a real throwaway SSH key and real SSHSIG signatures.

The tests exercise the actual ssh-keygen binary end to end — no mocked
crypto — so a passing suite means the kernel interoperates with OpenSSH.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

HAVE_SSH_KEYGEN = shutil.which("ssh-keygen") is not None


class KeyPair:
    """A passphrase-less ed25519 keypair in a temp dir, able to sign."""

    def __init__(self, comment: str = "wedge-rp-test") -> None:
        self._dir = tempfile.TemporaryDirectory(prefix="wedge-rp-test-")
        self.key_path = Path(self._dir.name) / "key"
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-q",
             "-f", str(self.key_path)],
            check=True,
            capture_output=True,
        )
        self.public_key = (self.key_path.with_suffix(".pub")).read_text("utf-8").strip()

    def sign(self, challenge: str, namespace: str) -> str:
        """Armored SSHSIG over the challenge bytes, like the wedge app makes."""
        proc = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(self.key_path), "-n", namespace],
            input=challenge.encode("utf-8"),
            capture_output=True,
            check=True,
        )
        return proc.stdout.decode("utf-8")

    def close(self) -> None:
        self._dir.cleanup()
