"""Signature-verification kernel.

Shells out to ``ssh-keygen -Y verify`` (OpenSSH 8.1+), so wedge-rp implements no
cryptography of its own — verification behaves exactly like sshd's
allowed_signers handling. Only public keys and signatures pass through here;
private keys never leave the user's ssh-agent.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

__all__ = ["verify_signature", "split_public_key", "same_key", "SSHKeygenUnavailable"]

# The principal is the first token of an allowed_signers line, so it must be a
# single inert token: no whitespace, and none of the characters ssh-keygen
# treats as comments, quoting, or patterns ("#", '"', "*", "?", ",").
PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9._@+=-]{1,256}$")

_KEYTYPE_RE = re.compile(r"^[A-Za-z0-9@.-]{1,64}$")
_KEYDATA_RE = re.compile(r"^[A-Za-z0-9+/=]{1,16384}$")
_SIG_HEADER = "-----BEGIN SSH SIGNATURE-----"
_MAX_SIGNATURE_BYTES = 64 * 1024


class SSHKeygenUnavailable(Exception):
    """ssh-keygen is missing or too old for ``-Y verify`` (needs OpenSSH 8.1+)."""


def split_public_key(public_key: str) -> tuple[str, str] | None:
    """Return ``(keytype, base64data)`` from an OpenSSH public-key line, dropping
    any trailing comment; ``None`` if the line doesn't look like a public key."""
    fields = public_key.strip().split()
    if len(fields) < 2:
        return None
    keytype, keydata = fields[0], fields[1]
    if not _KEYTYPE_RE.fullmatch(keytype) or not _KEYDATA_RE.fullmatch(keydata):
        return None
    return keytype, keydata


def same_key(a: str, b: str) -> bool:
    """Whether two public-key lines denote the same key (type + data; comments
    and surrounding whitespace ignored)."""
    pa = split_public_key(a)
    return pa is not None and pa == split_public_key(b)


def verify_signature(
    challenge: str,
    signature: str,
    *,
    principal: str,
    public_key: str,
    namespace: str,
    timeout: float = 10.0,
) -> tuple[bool, str]:
    """Verify an armored SSHSIG ``signature`` over the exact bytes of
    ``challenge``, made with ``namespace``, against ``public_key``.

    Returns ``(ok, detail)``. Malformed inputs and failed verification return
    ``(False, reason)``; a missing or pre-8.1 ssh-keygen raises
    :class:`SSHKeygenUnavailable` (server misconfiguration, not a bad login).
    """
    if not PRINCIPAL_RE.fullmatch(principal or ""):
        return False, "invalid principal"
    key = split_public_key(public_key or "")
    if key is None:
        return False, "malformed public key"
    if (
        not isinstance(signature, str)
        or not signature.lstrip().startswith(_SIG_HEADER)
        or len(signature) > _MAX_SIGNATURE_BYTES
    ):
        return False, "malformed signature"
    if not namespace or "\n" in namespace or "\x00" in namespace:
        return False, "invalid namespace"

    with tempfile.TemporaryDirectory(prefix="wedge-rp-") as tmp:
        allowed = Path(tmp) / "allowed_signers"
        sigfile = Path(tmp) / "challenge.sig"
        allowed.write_text(f"{principal} {key[0]} {key[1]}\n", encoding="utf-8")
        sigfile.write_text(signature.strip() + "\n", encoding="utf-8")
        cmd = [
            "ssh-keygen",
            "-Y", "verify",
            "-f", str(allowed),
            "-I", principal,
            "-n", namespace,
            "-s", str(sigfile),
        ]
        try:
            proc = subprocess.run(
                cmd,
                input=challenge.encode("utf-8"),
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            raise SSHKeygenUnavailable("ssh-keygen not found — install openssh-client") from None
        except subprocess.TimeoutExpired:
            return False, "verification timed out"

    stderr = proc.stderr.decode("utf-8", "replace").strip()
    stdout = proc.stdout.decode("utf-8", "replace").strip()
    if proc.returncode == 0:
        return True, stdout or "signature verified"
    if "unknown option" in stderr or stderr.lower().startswith("usage:"):
        raise SSHKeygenUnavailable("ssh-keygen lacks -Y verify — OpenSSH 8.1+ required")
    return False, stderr or stdout or "signature verification failed"
