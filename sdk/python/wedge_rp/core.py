"""Framework-neutral wedge relying-party engine.

:class:`WedgeRP` implements every RP-side requirement of the wedge protocol v1
(``docs/wedge-spec-v1.md``) as plain-data handlers — dicts in, dicts out. An
adapter (``wedge_rp.flask``, or ~60 lines of your own routing; see
``examples/wsgiref_demo.py``) translates HTTP to these calls; nothing in this
module imports a web framework.

The host application supplies what the spec deliberately leaves out of scope:
how accounts and their registered public keys are stored (the ``find_keys`` /
``find_user_by_public_key`` callbacks) and how a session is minted (adapters
take a ``login`` callback).
"""

from __future__ import annotations

import collections
import hmac
import re
import secrets
import threading
import time
from typing import Callable
from urllib.parse import quote, urlencode, urlsplit

from .kernel import (
    PRINCIPAL_RE,
    SSHKeygenUnavailable,
    split_public_key,
    verify_signature,
)
from .store import MemoryStore, RequestRecord, RequestStore

__all__ = [
    "WedgeRP",
    "normalize_origin",
    "equivalent_origins",
    "DISCOVERY_PATH",
    "START_PATH",
    "CHALLENGE_PATH",
    "VERIFY_PATH",
    "STATUS_PATH",
    "APP_START_PATH",
    "CLAIM_PATH",
    "SCRIPT_PATH",
    "BINDING_COOKIE",
]

# /.well-known/wedge.json and /wedge/app-start are fixed by the spec (§4, §9);
# the rest are this package's defaults — challenge/verify are published via
# discovery, start/status/claim are wired to the matching wedge.js.
DISCOVERY_PATH = "/.well-known/wedge.json"
START_PATH = "/wedge/start"
CHALLENGE_PATH = "/wedge/challenge"
VERIFY_PATH = "/wedge/verify"
STATUS_PATH = "/wedge/status"
APP_START_PATH = "/wedge/app-start"
CLAIM_PATH = "/wedge/claim"
SCRIPT_PATH = "/wedge/wedge.js"

BINDING_COOKIE = "wedge_flow"

# Must stay byte-identical to the authenticator's validation (spec §6.2 and
# wedge's internal/policy) — these are a security boundary.
CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

DEFAULT_CHALLENGE_TTL = 180.0


def normalize_origin(value: str) -> str:
    """Normalize to ``scheme://host[:port]`` (mirrors wedge's
    ``policy.NormalizeOrigin``: no default-port stripping, no path). Raises
    ``ValueError`` for anything that isn't a plain http(s) origin."""
    parts = urlsplit(value.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"not an http(s) origin: {value!r}")
    host = parts.hostname
    if ":" in host:  # IPv6 literal
        host = f"[{host}]"
    origin = f"{parts.scheme}://{host}"
    if parts.port is not None:
        origin += f":{parts.port}"
    return origin


def equivalent_origins(origin: str) -> list[str]:
    """The origin plus its localhost↔127.0.0.1 alias with the same scheme and
    port (spec §6.1; mirrors wedge's ``policy.EquivalentOrigins``)."""
    origins = [origin]
    parts = urlsplit(origin)
    alias = {"localhost": "127.0.0.1", "127.0.0.1": "localhost"}.get(parts.hostname or "")
    if alias:
        alt = f"{parts.scheme}://{alias}"
        if parts.port is not None:
            alt += f":{parts.port}"
        origins.append(alt)
    return origins


class _SlidingWindow:
    """Per-key sliding-window rate limiter (best-effort, per-process)."""

    def __init__(self, limit: int, window: float) -> None:
        self._limit = limit
        self._window = window
        self._events: dict[str, collections.deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            events = self._events.setdefault(key, collections.deque())
            while events and events[0] <= now - self._window:
                events.popleft()
            if len(events) >= self._limit:
                return False
            events.append(now)
            return True


class WedgeRP:
    """One instance per site. All handlers are thread-safe.

    :param origin: the site's canonical origin exactly as browsers reach it
        (``https://example.com``, ``http://127.0.0.1:8080``). Under the
        protocol's namespace==origin rule this string *is* the signature
        namespace, so it must be configured explicitly — never derived from a
        Host header an attacker can influence.
    :param find_keys: ``username -> list[str] | str | None`` — the registered
        public key(s) for an account. Enables username-carrying sign-in.
    :param find_user_by_public_key: ``public_key -> (username, keys) | None``
        — locate the account that registered a key (compare with
        :func:`wedge_rp.kernel.same_key`; type+data, comments ignored).
        Enables keyless sign-in and the app-initiated flow. The posted key is
        only ever a *selector*: verification runs strictly against the stored
        keys you return (spec §5.2).
    :param store: a :class:`RequestStore`; defaults to a per-process
        :class:`MemoryStore`. Multi-worker servers need :class:`SQLiteStore`
        or another shared store.
    """

    def __init__(
        self,
        *,
        origin: str,
        find_keys: Callable[[str], list[str] | str | None] | None = None,
        find_user_by_public_key: Callable[[str], tuple[str, list[str] | str] | None] | None = None,
        store: RequestStore | None = None,
        challenge_ttl: float = DEFAULT_CHALLENGE_TTL,
        verify_timeout: float = 10.0,
        max_concurrent_verifies: int = 4,
        verify_rate_limit: tuple[int, float] | None = (30, 60.0),
    ) -> None:
        if find_keys is None and find_user_by_public_key is None:
            raise ValueError("supply find_keys and/or find_user_by_public_key")
        self.origin = normalize_origin(origin)
        self.challenge_ttl = float(challenge_ttl)
        self._find_keys = find_keys
        self._find_user_by_public_key = find_user_by_public_key
        self._store = store if store is not None else MemoryStore()
        self._verify_timeout = float(verify_timeout)
        self._verify_slots = threading.BoundedSemaphore(max_concurrent_verifies)
        self._rate = _SlidingWindow(*verify_rate_limit) if verify_rate_limit else None

    # -- helpers -------------------------------------------------------------

    @property
    def uses_https(self) -> bool:
        """Whether the configured origin is https (adapters use this for the
        binding cookie's Secure attribute)."""
        return self.origin.startswith("https://")

    def is_same_origin(self, value: str | None) -> bool:
        """Whether an Origin/Referer header value matches this site (alias-
        aware). Adapters should reject browser-facing POSTs that fail this."""
        if not value:
            return False
        try:
            candidate = normalize_origin(value)
        except ValueError:
            return False
        return candidate in equivalent_origins(self.origin)

    def _mint(
        self,
        *,
        username: str | None,
        browser_nonce: str | None,
        claim_token: str | None,
    ) -> RequestRecord:
        record = RequestRecord(
            request_id=secrets.token_urlsafe(18),
            challenge=secrets.token_urlsafe(24),
            namespace=self.origin,
            username=username,
            browser_nonce=browser_nonce,
            claim_token=claim_token,
            status="pending",
            authenticated_username=None,
            expires_at=time.time() + self.challenge_ttl,
        )
        self._store.put(record)
        return record

    def sign_link(self, request_id: str) -> str:
        """The ``wedge://`` link the browser opens for this request (spec §3)."""
        return (
            "wedge://sign?v=1"
            f"&origin={quote(self.origin, safe='')}"
            f"&request_id={quote(request_id, safe='')}"
        )

    def _live(self, request_id: str) -> RequestRecord | None:
        if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
            return None
        return self._store.get(request_id)

    # -- endpoint handlers ----------------------------------------------------

    def discovery(self) -> dict:
        """GET /.well-known/wedge.json (spec §4)."""
        return {
            "version": 1,
            "namespace": self.origin,
            "challenge_url": self.origin + CHALLENGE_PATH,
            "verify_url": self.origin + VERIFY_PATH,
        }

    def start(self, username: str | None = None) -> tuple[int, dict, str | None]:
        """POST /wedge/start (browser-facing; shape is the RP's choice, spec
        §5.4). Returns ``(http_status, body, browser_nonce)``; the adapter must
        set ``browser_nonce`` as an HttpOnly cookie — it is the browser binding
        that later gates session minting."""
        if username is not None:
            if not isinstance(username, str) or not PRINCIPAL_RE.fullmatch(username):
                return 400, {"ok": False, "error": "invalid username"}, None
            if self._find_keys is None:
                return 400, {"ok": False, "error": "username sign-in is not supported"}, None
        elif self._find_user_by_public_key is None:
            return 400, {"ok": False, "error": "username required"}, None
        nonce = secrets.token_urlsafe(24)
        record = self._mint(username=username, browser_nonce=nonce, claim_token=None)
        body = {
            "ok": True,
            "request_id": record.request_id,
            "link": self.sign_link(record.request_id),
        }
        return 200, body, nonce

    def challenge(self, request_id: str) -> tuple[int, dict]:
        """GET <challenge_url>?request_id=… (spec §5.1)."""
        record = self._live(request_id)
        if record is None or record.status != "pending":
            return 404, {"ok": False, "error": "unknown request"}
        return 200, {"challenge": record.challenge, "namespace": record.namespace}

    def app_start(self) -> tuple[int, dict]:
        """POST /wedge/app-start (spec §8.1; path fixed in v1). Rejected with an
        explanatory error when the host has no keyless account lookup — the RP
        is then a conforming Core-only implementation (spec §8)."""
        if self._find_user_by_public_key is None:
            return 404, {"ok": False, "error": "app-initiated sign-in is not supported by this site"}
        claim_token = secrets.token_urlsafe(24)
        record = self._mint(username=None, browser_nonce=None, claim_token=claim_token)
        claim_url = (
            self.origin
            + CLAIM_PATH
            + "?"
            + urlencode({"request_id": record.request_id, "claim": claim_token})
        )
        return 200, {
            "ok": True,
            "request_id": record.request_id,
            "challenge": record.challenge,
            "namespace": record.namespace,
            "claim_url": claim_url,
        }

    def verify(self, body: object, *, source: str | None = None) -> tuple[int, dict]:
        """POST <verify_url> (spec §5.2; cookieless JSON from the authenticator).

        Verifies against the *stored* challenge and the account's *registered*
        keys — the echoed ``challenge`` field is ignored and a posted
        ``public_key`` is only an account selector. A failed verify consumes
        nothing, so the authenticator may retry with its next key.
        """
        if not isinstance(body, dict):
            return 400, {"ok": False, "error": "malformed request body"}
        record = self._live(body.get("request_id", ""))
        if record is None or record.status != "pending":
            return 404, {"ok": False, "error": "unknown request"}

        namespace = body.get("namespace")
        if not isinstance(namespace, str) or not self.is_same_origin(namespace):
            return 400, {"ok": False, "error": "namespace mismatch"}
        signature = body.get("signature")
        if not isinstance(signature, str) or not signature.lstrip().startswith("-----BEGIN SSH SIGNATURE-----"):
            return 400, {"ok": False, "error": "malformed signature"}

        if self._rate is not None and source and not self._rate.allow(source):
            return 429, {"ok": False, "error": "rate limited"}

        candidates = self._resolve_candidates(record, body.get("public_key"))
        if isinstance(candidates, tuple):  # (status, body) error short-circuit
            return candidates

        if not self._verify_slots.acquire(blocking=False):
            return 503, {"ok": False, "error": "verifier busy"}
        try:
            for username, stored_key in candidates:
                # -n gets the namespace string the authenticator actually
                # signed (it echoes what we minted; alias variants of our
                # origin are equivalent by §6.1 but the bytes must match).
                ok, _detail = verify_signature(
                    record.challenge,
                    signature,
                    principal=username,
                    public_key=stored_key,
                    namespace=namespace,
                    timeout=self._verify_timeout,
                )
                if ok:
                    if not self._store.set_authenticated(record.request_id, username):
                        return 404, {"ok": False, "error": "unknown request"}
                    return 200, {"ok": True}
        except SSHKeygenUnavailable as exc:
            return 503, {"ok": False, "error": str(exc)}
        finally:
            self._verify_slots.release()
        return 401, {"ok": False, "error": "signature verification failed"}

    def _resolve_candidates(
        self, record: RequestRecord, posted_key: object
    ) -> list[tuple[str, str]] | tuple[int, dict]:
        """The (username, registered_key) pairs to verify against, or an
        ``(http_status, body)`` error."""
        if record.username is not None:
            assert self._find_keys is not None  # enforced at start()
            keys = self._find_keys(record.username)
            if isinstance(keys, str):
                keys = [keys]
            if not keys:
                return 401, {"ok": False, "error": "no account matches"}
            return [(record.username, key) for key in keys]
        # Keyless: the posted public key is REQUIRED (spec §8.2) and is only a
        # selector — verification runs against the stored keys.
        if not isinstance(posted_key, str) or split_public_key(posted_key) is None:
            return 400, {"ok": False, "error": "public_key required"}
        assert self._find_user_by_public_key is not None  # enforced at start/app_start
        match = self._find_user_by_public_key(posted_key)
        if match is None:
            return 401, {"ok": False, "error": "no account matches key"}
        username, stored = match
        if not PRINCIPAL_RE.fullmatch(username or ""):
            return 401, {"ok": False, "error": "no account matches key"}
        stored_keys = [stored] if isinstance(stored, str) else list(stored)
        return [(username, key) for key in stored_keys]

    def status(self, request_id: str, browser_nonce: str | None) -> tuple[dict, str | None]:
        """GET /wedge/status?request_id=… (browser-facing, spec §5.4). Returns
        ``(body, username)``. A non-None ``username`` means the browser binding
        checked out and the request was atomically consumed — the adapter must
        mint the host session *now* (this is the only moment it can)."""
        record = self._live(request_id)
        if record is None:
            return {"status": "expired"}, None
        if record.browser_nonce is None:
            # App-initiated requests complete via /wedge/claim, never polling.
            return {"status": "pending"}, None
        if not browser_nonce or not hmac.compare_digest(browser_nonce, record.browser_nonce):
            return {"status": "pending"}, None
        if record.status != "authenticated":
            return {"status": record.status}, None
        taken = self._store.take_authenticated(record.request_id)
        if taken is None or taken.authenticated_username is None:
            return {"status": "pending"}, None
        return {"status": "authenticated"}, taken.authenticated_username

    def claim(self, request_id: str, claim_token: str | None) -> str | None:
        """GET /wedge/claim?request_id=…&claim=… (spec §8.3). Returns the
        username to mint a session for, or None (adapter redirects to a login
        or error page — never minting). The record is removed (= the claim is
        marked used) *before* the username is returned."""
        record = self._live(request_id)
        if (
            record is None
            or record.claim_token is None
            or record.status != "authenticated"
            or not isinstance(claim_token, str)
            or not claim_token
            or not hmac.compare_digest(claim_token, record.claim_token)
        ):
            return None
        taken = self._store.take_authenticated(record.request_id)
        if taken is None:
            return None
        return taken.authenticated_username
