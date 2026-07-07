#!/usr/bin/env python3
import json
import os
import re
import stat
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

MAX_MESSAGE_BYTES = 64 * 1024
DEFAULT_SIGN_TIMEOUT_SECONDS = 10.0
CHALLENGE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
NAMESPACE_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")


def read_message() -> Optional[Dict[str, Any]]:
    raw_length = os.read(0, 4)
    if len(raw_length) == 0:
        return None
    if len(raw_length) < 4:
        raise RuntimeError("Invalid native message length prefix")
    message_length = struct.unpack("<I", raw_length)[0]
    if message_length <= 0 or message_length > MAX_MESSAGE_BYTES:
        raise RuntimeError(f"Invalid native message size: {message_length}")
    payload = b""
    while len(payload) < message_length:
        chunk = os.read(0, message_length - len(payload))
        if not chunk:
            break
        payload += chunk
    if len(payload) != message_length:
        raise RuntimeError("Failed reading complete native message")
    return json.loads(payload.decode("utf-8"))


def write_message(message: Dict[str, Any]) -> None:
    encoded = json.dumps(message).encode("utf-8")
    os.write(1, struct.pack("<I", len(encoded)))
    os.write(1, encoded)


def resolve_key_path(key_path_override: str = "") -> Path:
    key_path = key_path_override.strip() or os.environ.get("PUBKEY_AUTH_KEY_PATH", str(Path.home() / ".ssh" / "id_ed25519"))
    return Path(key_path).expanduser()


def validate_key_file(key_file: Path) -> None:
    if not key_file.exists():
        raise RuntimeError(f"key file not found: {key_file}")
    if not key_file.is_file():
        raise RuntimeError(f"key path is not a regular file: {key_file}")

    key_stat = key_file.stat(follow_symlinks=False)
    if stat.S_ISLNK(key_stat.st_mode):
        raise RuntimeError(f"key path must not be a symlink: {key_file}")
    # POSIX ownership/permission checks do not map directly to Windows ACLs.
    # Keep strict checks where supported and skip on Windows.
    current_uid = None
    getuid = getattr(os, "getuid", None)
    if callable(getuid):
        try:
            current_uid = getuid()
        except Exception:
            current_uid = None
    if current_uid is not None and key_stat.st_uid != current_uid:
        raise RuntimeError(f"key file is not owned by current user: {key_file}")
    if os.name != "nt":
        mode = stat.S_IMODE(key_stat.st_mode)
        if mode & 0o077:
            raise RuntimeError(f"key file permissions are too open ({oct(mode)}), expected 0o600 or stricter")


def run_sign(challenge: str, namespace: str, key_path_override: str = "") -> str:
    keygen = os.environ.get("SSH_KEYGEN_PATH", "ssh-keygen")
    key_file = resolve_key_path(key_path_override)
    timeout_raw = os.environ.get("PUBKEY_AUTH_SIGN_TIMEOUT_SECONDS", str(DEFAULT_SIGN_TIMEOUT_SECONDS))
    try:
        timeout_seconds = float(timeout_raw)
        if timeout_seconds <= 0:
            raise ValueError("timeout must be positive")
    except ValueError as exc:
        raise RuntimeError(f"invalid PUBKEY_AUTH_SIGN_TIMEOUT_SECONDS value: {timeout_raw}") from exc

    if not challenge.strip():
        raise RuntimeError("challenge is empty")
    if not namespace.strip():
        raise RuntimeError("namespace is empty")
    if not CHALLENGE_PATTERN.fullmatch(challenge.strip()):
        raise RuntimeError("invalid challenge format")
    if not NAMESPACE_PATTERN.fullmatch(namespace.strip()):
        raise RuntimeError("invalid namespace format")

    validate_key_file(key_file)

    with tempfile.TemporaryDirectory(prefix="pubkey-auth-") as td:
        challenge_file = Path(td) / "challenge"
        sig_file = Path(td) / "challenge.sig"

        challenge_file.write_text(challenge, encoding="utf-8")

        cmd = [
            keygen,
            "-Y",
            "sign",
            "-f",
            str(key_file),
            "-n",
            namespace,
            str(challenge_file),
        ]
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"ssh-keygen sign timed out after {timeout_seconds:g}s") from exc
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            raise RuntimeError(f"ssh-keygen sign failed (code {proc.returncode}): {stderr or stdout or 'unknown error'}")

        if not sig_file.exists():
            raise RuntimeError("signature file was not created by ssh-keygen")

        signature = sig_file.read_text(encoding="utf-8").strip()
        if not signature:
            raise RuntimeError("signature file is empty")
        return signature


def validate_key(key_path_override: str = "") -> None:
    validate_key_file(resolve_key_path(key_path_override))


def main() -> None:
    try:
        msg = read_message()
        if msg is None:
            return

        msg_type = str(msg.get("type", "")).strip()
        if msg_type == "PING":
            write_message({"ok": True})
            return

        if msg_type == "VALIDATE_KEY":
            key_path = str(msg.get("keyPath", msg.get("key_path", "")))
            validate_key(key_path)
            write_message({"ok": True})
            return

        if msg_type != "SIGN_CHALLENGE":
            write_message({"ok": False, "error": f"unsupported request type: {msg_type}"})
            return

        challenge = str(msg.get("challenge", ""))
        namespace = str(msg.get("namespace", ""))
        key_path = str(msg.get("keyPath", msg.get("key_path", "")))
        signature = run_sign(challenge, namespace, key_path)
        write_message({"ok": True, "signature": signature})
    except Exception as exc:
        write_message({"ok": False, "error": str(exc)})


if __name__ == "__main__":
    main()
