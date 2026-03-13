# This future-import is load-bearing, as `hashlib._Hash` is not actually importable.
from __future__ import annotations

import os
import hashlib
from collections.abc import Callable, Iterable
from hashlib import md5 as _md5
from hashlib import sha1 as _sha1
from hashlib import sha256 as _sha256
from typing import Any

from django.utils.encoding import force_bytes

# FIPS 140-3: when SENTRY_FIPS_MODE is set, we use SHA-256 instead of MD5 for non-grouping hashes.
# We do not import sentry.options here to avoid circular imports (options.manager imports this module).
_FIPS_MODE_ENV = "SENTRY_FIPS_MODE"

# Truncate SHA-256 hex digest to this length for drop-in replacement of MD5 (32 hex chars).
_FIPS_KEY_HASH_LEN = 32


def _fips_mode() -> bool:
    return os.environ.get(_FIPS_MODE_ENV, "").lower() in ("1", "true", "yes")


class _TruncatedSHA256Digest:
    """Wrapper that exposes .hexdigest() truncated to _FIPS_KEY_HASH_LEN for key compatibility.
    .digest() returns first 16 bytes so .digest()[0] and similar use cases work."""

    __slots__ = ("_hash",)

    def __init__(self) -> None:
        self._hash = _sha256()

    def update(self, data: bytes) -> None:
        self._hash.update(data)

    def hexdigest(self) -> str:
        return self._hash.hexdigest()[:_FIPS_KEY_HASH_LEN]

    def digest(self) -> bytes:
        return self._hash.digest()[:16]


def md5_text(*args: Any) -> hashlib._Hash:
    """Hash text for cache keys, rate limits, etc. In FIPS mode uses SHA-256 (truncated to 32 hex chars)."""
    if _fips_mode():
        m = _TruncatedSHA256Digest()
        for x in args:
            m.update(force_bytes(x, errors="replace"))
        return m  # type: ignore[return-value]
    m = _md5()
    for x in args:
        m.update(force_bytes(x, errors="replace"))
    return m


def sha1_text(*args: Any) -> hashlib._Hash:
    m = _sha1()
    for x in args:
        m.update(force_bytes(x, errors="replace"))
    return m


def sha256_text(*args: Any) -> hashlib._Hash:
    m = _sha256()
    for x in args:
        m.update(force_bytes(x, errors="replace"))
    return m


def hash_value(h: hashlib._Hash, value: Any) -> None:
    if value is None:
        h.update(b"\x00")
    elif value is True:
        h.update(b"\x01")
    elif value is False:
        h.update(b"\x02")
    elif isinstance(value, int):
        h.update(b"\x03" + str(value).encode("ascii") + b"\x00")
    elif isinstance(value, (tuple, list)):
        h.update(b"\x04" + str(len(value)).encode("utf-8"))
        for item in value:
            hash_value(h, item)
    elif isinstance(value, dict):
        h.update(b"\x05" + str(len(value)).encode("utf-8"))
        for k, v in sorted(value.items()):
            hash_value(h, k)
            hash_value(h, v)
    elif isinstance(value, bytes):
        h.update(b"\x06" + value + b"\x00")
    elif isinstance(value, str):
        h.update(b"\x07" + value.encode("utf-8") + b"\x00")
    else:
        raise TypeError("Invalid hash value")


def hash_values(
    values: Iterable[Any],
    seed: str | None = None,
    algorithm: Callable[[], hashlib._Hash] | None = None,
) -> str:
    """Returns a hexadecimal hash from an iterable data structure.
    Uses SHA-256 in FIPS mode, otherwise MD5 by default.
    You can optionally include a seed to help determine where in the code the values were hashed.
    """
    if algorithm is None:
        algorithm = _sha256 if _fips_mode() else _md5
    _hash = algorithm()
    if seed:
        _hash.update(("%s\xff" % seed).encode("utf-8"))
    for value in values:
        hash_value(_hash, value)
    return _hash.hexdigest()


def fnv1a_32(data: bytes) -> int:
    """
    Fowler–Noll–Vo hash function 32 bit implementation.
    """
    fnv_init = 0x811C9DC5
    fnv_prime = 0x01000193
    fnv_size = 2**32

    result_hash = fnv_init
    for byte in data:
        result_hash ^= byte
        result_hash = (result_hash * fnv_prime) % fnv_size

    return result_hash
