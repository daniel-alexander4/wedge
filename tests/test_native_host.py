import importlib.util
import os
import stat
import tempfile
import unittest
from unittest import mock
from pathlib import Path


def load_native_host_module():
    repo_root = Path(__file__).resolve().parent.parent
    module_path = repo_root / "native-host" / "com.pubkey.auth.py"
    spec = importlib.util.spec_from_file_location("pubkey_auth_host", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load native host module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NativeHostFailureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = load_native_host_module()

    def create_key_file(self, directory: str) -> Path:
        key_file = Path(directory) / "id_test"
        key_file.write_text("dummy-private-key", encoding="utf-8")
        os.chmod(key_file, stat.S_IRUSR | stat.S_IWUSR)
        return key_file

    def create_executable(self, directory: str, content: str) -> Path:
        script = Path(directory) / "fake-keygen.sh"
        script.write_text(content, encoding="utf-8")
        os.chmod(script, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        return script

    def setUp(self):
        self._old_ssh_keygen = os.environ.get("SSH_KEYGEN_PATH")
        self._old_timeout = os.environ.get("PUBKEY_AUTH_SIGN_TIMEOUT_SECONDS")

    def tearDown(self):
        if self._old_ssh_keygen is None:
            os.environ.pop("SSH_KEYGEN_PATH", None)
        else:
            os.environ["SSH_KEYGEN_PATH"] = self._old_ssh_keygen
        if self._old_timeout is None:
            os.environ.pop("PUBKEY_AUTH_SIGN_TIMEOUT_SECONDS", None)
        else:
            os.environ["PUBKEY_AUTH_SIGN_TIMEOUT_SECONDS"] = self._old_timeout

    def test_sign_returns_error_when_ssh_keygen_fails(self):
        with tempfile.TemporaryDirectory(prefix="sshkey-web-auth-test-") as td:
            key_file = self.create_key_file(td)
            fake_keygen = self.create_executable(
                td,
                "#!/usr/bin/env bash\n"
                "echo 'simulated sign failure' >&2\n"
                "exit 17\n",
            )
            os.environ["SSH_KEYGEN_PATH"] = str(fake_keygen)
            os.environ.pop("PUBKEY_AUTH_SIGN_TIMEOUT_SECONDS", None)
            with self.assertRaises(RuntimeError) as err:
                self.host.run_sign("AbCdEfGhIjKlMnOp_1234", "myapp", str(key_file))
            self.assertIn("ssh-keygen sign failed", str(err.exception))
            self.assertIn("code 17", str(err.exception))

    def test_sign_returns_error_when_ssh_keygen_times_out(self):
        with tempfile.TemporaryDirectory(prefix="sshkey-web-auth-test-") as td:
            key_file = self.create_key_file(td)
            fake_keygen = self.create_executable(
                td,
                "#!/usr/bin/env bash\n"
                "sleep 2\n"
                "exit 0\n",
            )
            os.environ["SSH_KEYGEN_PATH"] = str(fake_keygen)
            os.environ["PUBKEY_AUTH_SIGN_TIMEOUT_SECONDS"] = "0.1"
            with self.assertRaises(RuntimeError) as err:
                self.host.run_sign("AbCdEfGhIjKlMnOp_1234", "myapp", str(key_file))
            self.assertIn("timed out", str(err.exception))

    def test_sign_does_not_crash_when_getuid_is_unavailable(self):
        with tempfile.TemporaryDirectory(prefix="sshkey-web-auth-test-") as td:
            key_file = self.create_key_file(td)
            fake_keygen = self.create_executable(
                td,
                "#!/usr/bin/env bash\n"
                "echo 'simulated sign failure' >&2\n"
                "exit 17\n",
            )
            os.environ["SSH_KEYGEN_PATH"] = str(fake_keygen)
            os.environ.pop("PUBKEY_AUTH_SIGN_TIMEOUT_SECONDS", None)
            with mock.patch.object(self.host.os, "getuid", None):
                with self.assertRaises(RuntimeError) as err:
                    self.host.run_sign("AbCdEfGhIjKlMnOp_1234", "myapp", str(key_file))
            self.assertIn("ssh-keygen sign failed", str(err.exception))

    def test_sign_rejects_invalid_challenge_format(self):
        with tempfile.TemporaryDirectory(prefix="sshkey-web-auth-test-") as td:
            key_file = self.create_key_file(td)
            with self.assertRaises(RuntimeError) as err:
                self.host.run_sign("bad!!", "myapp", str(key_file))
            self.assertIn("invalid challenge format", str(err.exception))

    def test_sign_rejects_invalid_namespace_format(self):
        with tempfile.TemporaryDirectory(prefix="sshkey-web-auth-test-") as td:
            key_file = self.create_key_file(td)
            with self.assertRaises(RuntimeError) as err:
                self.host.run_sign("AbCdEfGhIjKlMnOp_1234", "bad namespace", str(key_file))
            self.assertIn("invalid namespace format", str(err.exception))


if __name__ == "__main__":
    unittest.main()
