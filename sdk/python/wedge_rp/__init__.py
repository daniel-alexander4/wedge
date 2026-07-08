"""wedge-rp — relying-party middleware for wedge (SSH-key web authentication).

Add "Sign in with wedge" to a Python web app: create a :class:`WedgeRP` with
your site's origin and account-lookup callbacks, then mount it — via the Flask
blueprint (``wedge_rp.flask.wedge_blueprint``) or your own thin routing over
the framework-neutral handlers. Wire spec: docs/wedge-spec-v1.md in the wedge
repository.
"""

from .core import (
    APP_START_PATH,
    BINDING_COOKIE,
    CHALLENGE_PATH,
    CLAIM_PATH,
    DISCOVERY_PATH,
    SCRIPT_PATH,
    START_PATH,
    STATUS_PATH,
    VERIFY_PATH,
    WedgeRP,
    equivalent_origins,
    normalize_origin,
)
from .kernel import SSHKeygenUnavailable, same_key, split_public_key, verify_signature
from .store import MemoryStore, RequestRecord, RequestStore, SQLiteStore

__version__ = "0.1.0"

__all__ = [
    "WedgeRP",
    "MemoryStore",
    "SQLiteStore",
    "RequestStore",
    "RequestRecord",
    "verify_signature",
    "same_key",
    "split_public_key",
    "SSHKeygenUnavailable",
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
    "__version__",
]
