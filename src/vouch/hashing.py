"""BLAKE3 digest helpers. All digests in Vouch are BLAKE3, 256-bit, rendered
as ``b3:<hex>`` per 02_TECHNICAL_ARCHITECTURE.md section 3.1.
"""

from __future__ import annotations

import re

import blake3

DIGEST_PREFIX = "b3:"
_DIGEST_RE = re.compile(r"^b3:[0-9a-f]{64}$")


def new_hasher():
    """Return a fresh streaming BLAKE3 hasher."""
    return blake3.blake3()


def b3_hex(data: bytes) -> str:
    """Hash ``data`` and render as ``b3:<hex>``."""
    return DIGEST_PREFIX + blake3.blake3(data).hexdigest()


def format_digest(raw_digest: bytes) -> str:
    """Render a raw 32-byte digest as ``b3:<hex>``."""
    return DIGEST_PREFIX + raw_digest.hex()


def parse_b3(digest: str) -> bytes:
    """Parse a ``b3:<hex>`` string into raw digest bytes. Raises ValueError if malformed."""
    if not is_valid_digest(digest):
        raise ValueError(f"not a valid b3 digest: {digest!r}")
    return bytes.fromhex(digest[len(DIGEST_PREFIX):])


def is_valid_digest(digest: str) -> bool:
    return bool(_DIGEST_RE.match(digest))
