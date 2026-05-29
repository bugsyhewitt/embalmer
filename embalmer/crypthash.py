"""Pure-Python Unix crypt(3) hash verification.

embalmer's credential scanner recovers ``/etc/shadow``-style password hashes
from firmware. Knowing a hash *exists* tells an analyst a password is set;
knowing the hash matches a *default/weak* password tells them the device ships
with a credential an attacker already has — the single most-exploited class of
IoT firmware weakness (Mirai and its descendants spread almost entirely through
default credentials).

To check a candidate plaintext against a stored crypt hash we must recompute the
hash under the same scheme and salt and compare. Python 3.13 removed the stdlib
``crypt`` module (PEP 594), and embalmer is dependency-light by design, so this
module reimplements the handful of crypt schemes that actually occur in firmware
shadow files, using only :mod:`hashlib`:

* ``$1$`` — MD5-crypt (Poul-Henning Kamp's algorithm; ubiquitous on BusyBox
  and older embedded Linux);
* ``$5$`` — SHA-256-crypt (Drepper's algorithm, optional ``rounds=`` parameter);
* ``$6$`` — SHA-512-crypt (Drepper's algorithm; the modern glibc default).

These three ``$id$`` schemes cover the overwhelming majority of real firmware
shadow files (BusyBox and modern embedded Linux). Each implementation follows the
reference specification exactly and is cross-checked against ``openssl passwd`` in
the test suite, so the recomputed hash is byte-for-byte identical to what the
device's libc produced. The functions are deliberately *verification only*
(compare a guess to a stored hash); embalmer never needs to mint new hashes.

Out of scope: traditional 13-char DES crypt (extremely rare on shippable
firmware), and the modern memory-hard schemes ``$2*$`` bcrypt and ``$y$``
yescrypt — those are deliberately expensive to compute, so brute-forcing them
against a wordlist offline is not embalmer's job. :func:`identify_scheme` returns
``None`` for all of these so callers skip them cleanly.
"""

from __future__ import annotations

import hashlib

__all__ = ["identify_scheme", "verify", "CryptError"]


class CryptError(ValueError):
    """Raised for a malformed or unsupported crypt hash string."""


# The crypt(3) base64 alphabet (./0-9A-Za-z) used by MD5- and SHA-crypt for the
# final hash encoding. Note this is NOT standard base64.
_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def identify_scheme(stored: str) -> str | None:
    """Return a short scheme name for a stored crypt hash, or ``None``.

    Only schemes this module can verify are recognized. Disabled/locked account
    placeholders (``*``, ``!``, ``x``, empty), DES crypt, and the memory-hard
    schemes (``$2*$`` bcrypt, ``$y$`` yescrypt) return ``None`` so callers skip
    them rather than mis-classify them as crackable.
    """
    if not stored:
        return None
    if stored.startswith("$1$"):
        return "md5crypt"
    if stored.startswith("$5$"):
        return "sha256crypt"
    if stored.startswith("$6$"):
        return "sha512crypt"
    return None


def verify(plaintext: str, stored: str) -> bool:
    """Return True if ``plaintext`` hashes to ``stored`` under its own scheme.

    Returns False for any unsupported/locked hash rather than raising, so a
    cracking loop can call it uniformly across a shadow file.
    """
    scheme = identify_scheme(stored)
    if scheme is None:
        return False
    try:
        if scheme == "md5crypt":
            return _md5crypt(plaintext, stored) == stored
        if scheme == "sha256crypt":
            return _shacrypt(plaintext, stored, bits=256) == stored
        if scheme == "sha512crypt":
            return _shacrypt(plaintext, stored, bits=512) == stored
    except (CryptError, ValueError, IndexError):
        return False
    return False


# --------------------------------------------------------------------------- #
# $1$ — MD5-crypt
# --------------------------------------------------------------------------- #


def _to64(value: int, length: int) -> str:
    out = []
    for _ in range(length):
        out.append(_B64[value & 0x3F])
        value >>= 6
    return "".join(out)


def _md5crypt(password: str, stored: str) -> str:
    parts = stored.split("$")
    # ["", "1", salt, hash...]
    if len(parts) < 4 or parts[1] != "1":
        raise CryptError(f"not an md5crypt hash: {stored!r}")
    salt = parts[2][:8]
    pw = password.encode("utf-8", "surrogateescape")
    salt_b = salt.encode("ascii")

    # Per the reference algorithm.
    ctx = hashlib.md5(pw + b"$1$" + salt_b)
    alt = hashlib.md5(pw + salt_b + pw).digest()

    pw_len = len(pw)
    i = pw_len
    while i > 0:
        ctx.update(alt[: min(i, 16)])
        i -= 16

    i = pw_len
    while i:
        ctx.update(b"\x00" if (i & 1) else pw[:1])
        i >>= 1

    final = ctx.digest()
    for i in range(1000):
        c = hashlib.md5()
        c.update(pw if (i & 1) else final)
        if i % 3:
            c.update(salt_b)
        if i % 7:
            c.update(pw)
        c.update(final if (i & 1) else pw)
        final = c.digest()

    # Permuted base64 encoding.
    order = [
        (0, 6, 12),
        (1, 7, 13),
        (2, 8, 14),
        (3, 9, 15),
        (4, 10, 5),
    ]
    out = []
    for a, b, c in order:
        v = (final[a] << 16) | (final[b] << 8) | final[c]
        out.append(_to64(v, 4))
    out.append(_to64(final[11], 2))
    return f"$1$" + salt + "$" + "".join(out)


# --------------------------------------------------------------------------- #
# $5$ / $6$ — SHA-256-crypt and SHA-512-crypt (Ulrich Drepper's algorithm)
# --------------------------------------------------------------------------- #

_DEFAULT_ROUNDS = 5000
_MIN_ROUNDS = 1000
_MAX_ROUNDS = 999_999_999


def _shacrypt(password: str, stored: str, *, bits: int) -> str:
    if bits == 256:
        hasher = hashlib.sha256
        digest_len = 32
        prefix = "5"
    else:
        hasher = hashlib.sha512
        digest_len = 64
        prefix = "6"

    parts = stored.split("$")
    if len(parts) < 4 or parts[1] != prefix:
        raise CryptError(f"not a sha{bits}crypt hash: {stored!r}")

    idx = 2
    rounds = _DEFAULT_ROUNDS
    rounds_field = ""
    if parts[idx].startswith("rounds="):
        try:
            rounds = int(parts[idx].split("=", 1)[1])
        except ValueError as exc:
            raise CryptError(f"bad rounds field: {parts[idx]!r}") from exc
        rounds = max(_MIN_ROUNDS, min(_MAX_ROUNDS, rounds))
        rounds_field = f"rounds={rounds}$"
        idx += 1
    salt = parts[idx][:16]

    pw = password.encode("utf-8", "surrogateescape")
    salt_b = salt.encode("ascii")
    pw_len = len(pw)

    # Digest B.
    b_ctx = hasher(pw + salt_b + pw)
    digest_b = b_ctx.digest()

    # Digest A.
    a_ctx = hasher(pw + salt_b)
    i = pw_len
    while i > 0:
        a_ctx.update(digest_b[: min(i, digest_len)])
        i -= digest_len
    n = pw_len
    while n:
        a_ctx.update(digest_b if (n & 1) else pw)
        n >>= 1
    digest_a = a_ctx.digest()

    # Sequence P: digest DP (= H(password * len(password))) repeated to the
    # password's length.
    dp_ctx = hasher()
    for _ in range(pw_len):
        dp_ctx.update(pw)
    digest_dp = dp_ctx.digest()
    p_seq = (digest_dp * (pw_len // digest_len + 1))[:pw_len]

    # Sequence S: digest DS (= H(salt * (16 + A[0]))) repeated to the salt's
    # length.
    ds_ctx = hasher()
    for _ in range(16 + digest_a[0]):
        ds_ctx.update(salt_b)
    digest_ds = ds_ctx.digest()
    salt_len = len(salt_b)
    s_seq = (digest_ds * (salt_len // digest_len + 1))[:salt_len]

    # Rounds loop.
    digest_c = digest_a
    for r in range(rounds):
        c = hasher()
        c.update(p_seq if (r & 1) else digest_c)
        if r % 3:
            c.update(s_seq)
        if r % 7:
            c.update(p_seq)
        c.update(digest_c if (r & 1) else p_seq)
        digest_c = c.digest()

    encoded = _shacrypt_encode(digest_c, bits)
    return f"${prefix}${rounds_field}{salt}${encoded}"


# Byte-triplet permutation tables for the final base64 encoding, per the spec.
_SHA256_ORDER = [
    (0, 10, 20),
    (21, 1, 11),
    (12, 22, 2),
    (3, 13, 23),
    (24, 4, 14),
    (15, 25, 5),
    (6, 16, 26),
    (27, 7, 17),
    (18, 28, 8),
    (9, 19, 29),
]
_SHA512_ORDER = [
    (0, 21, 42),
    (22, 43, 1),
    (44, 2, 23),
    (3, 24, 45),
    (25, 46, 4),
    (47, 5, 26),
    (6, 27, 48),
    (28, 49, 7),
    (50, 8, 29),
    (9, 30, 51),
    (31, 52, 10),
    (53, 11, 32),
    (12, 33, 54),
    (34, 55, 13),
    (56, 14, 35),
    (15, 36, 57),
    (37, 58, 16),
    (59, 17, 38),
    (18, 39, 60),
    (40, 61, 19),
    (62, 20, 41),
]


def _shacrypt_encode(digest: bytes, bits: int) -> str:
    out = []
    if bits == 256:
        for a, b, c in _SHA256_ORDER:
            v = (digest[a] << 16) | (digest[b] << 8) | digest[c]
            out.append(_to64(v, 4))
        # Final two bytes: indices 31, 30.
        v = (digest[31] << 8) | digest[30]
        out.append(_to64(v, 3))
    else:
        for a, b, c in _SHA512_ORDER:
            v = (digest[a] << 16) | (digest[b] << 8) | digest[c]
            out.append(_to64(v, 4))
        # Final single byte: index 63.
        out.append(_to64(digest[63], 2))
    return "".join(out)
