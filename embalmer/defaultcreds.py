"""Default / weak credential detection.

Finding a ``/etc/shadow`` password *hash* tells an analyst a password is set.
Finding that the hash matches a *default or weak* password tells them the device
ships with a credential an attacker already knows — which is the single
most-exploited class of IoT firmware weakness. Mirai and essentially every
botnet after it spread by logging into devices with their factory-default
credentials; a 2024 CISA "Secure by Design" alert named hardcoded/default
credentials the most damaging recurring firmware flaw.

This module takes the shadow password hashes embalmer's credential scanner
already recovers and tries to *crack* them against a curated wordlist of the
default and trivially-weak passwords that actually ship on consumer/IoT devices
(``admin``, ``root``, ``1234``, ``vizxv``, the Mirai dictionary, vendor
defaults, …). A match is a confirmed-exploitable credential: embalmer promotes it
to ``critical`` and records the recovered plaintext so the analyst can see
*exactly* what the password is, not merely that one exists.

Hash verification is :mod:`embalmer.crypthash` — a pure-Python crypt(3)
implementation (Python 3.13 dropped the stdlib ``crypt`` module). No external
tool (``john``, ``hashcat``) is required; the wordlist is small and the schemes
firmware uses (``$1$`` md5crypt, ``$5$``/``$6$`` sha-crypt) are cheap to compute
a few hundred times.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import crypthash

__all__ = ["crack", "CrackResult", "DEFAULT_WORDLIST"]


# A curated wordlist of default and trivially-weak passwords that recur across
# consumer routers, IP cameras, DVRs, and other IoT devices. This is deliberately
# small and high-signal — it is the union of (a) the classic factory defaults
# (admin/root/password/1234), (b) the Mirai botnet's built-in credential
# dictionary (the passwords that compromised hundreds of thousands of devices in
# 2016 and that clones still use), and (c) common vendor service-account
# passwords. It is NOT a general password-cracking dictionary: embalmer's job is
# to flag *known-default* credentials, not to brute-force strong ones.
DEFAULT_WORDLIST: tuple[str, ...] = (
    # universal defaults
    "",  # empty password — a set-but-blank account
    "admin",
    "root",
    "password",
    "Password",
    "PASSWORD",
    "pass",
    "default",
    "guest",
    "user",
    "toor",
    "system",
    "service",
    "support",
    "test",
    "changeme",
    "letmein",
    "secret",
    # numeric defaults
    "1234",
    "12345",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "111111",
    "000000",
    "0000",
    "1111",
    "admin1234",
    "admin123",
    "root123",
    # admin/login combos
    "admin1",
    "adminadmin",
    "rootroot",
    "administrator",
    "abc123",
    "qwerty",
    "password1",
    "password123",
    # Mirai built-in credential dictionary (the passwords half) — the strings
    # baked into the original Mirai source's scanner table that compromised
    # hundreds of thousands of IoT devices.
    "vizxv",
    "xc3511",
    "888888",
    "54321",
    "juantech",
    "anko",
    "zlxx.",
    "7ujMko0vizxv",
    "7ujMko0admin",
    "ikwb",
    "dreambox",
    "realtek",
    "1111111",
    "meinsm",
    "klv123",
    "klv1234",
    "Zte521",
    "hi3518",
    "jvbzd",
    "GMB182",
    "smcadmin",
    "tlJwpbo6",
    "fucker",
    # common vendor service/maintenance passwords
    "epicrouter",
    "tech",
    "wlan",
    "private",
    "public",
    "cisco",
    "supervisor",
)


@dataclass(frozen=True)
class CrackResult:
    """The outcome of cracking one stored hash against the wordlist."""

    #: The crypt scheme of the hash (``"md5crypt"``, ``"sha256crypt"``,
    #: ``"sha512crypt"``), or ``None`` if the hash was not a crackable scheme.
    scheme: str | None
    #: The recovered plaintext password, or ``None`` if no wordlist entry matched.
    password: str | None

    @property
    def cracked(self) -> bool:
        return self.password is not None


def crack(stored_hash: str, wordlist: tuple[str, ...] = DEFAULT_WORDLIST) -> CrackResult:
    """Try every entry in ``wordlist`` against ``stored_hash``.

    Returns a :class:`CrackResult`. ``result.cracked`` is True (and
    ``result.password`` is the plaintext) when an entry's crypt hash equals
    ``stored_hash``. Unsupported/locked hashes are reported with ``scheme=None``
    and never crack. The first matching entry wins (the wordlist is ordered most-
    common-first), so the loop short-circuits.
    """
    scheme = crypthash.identify_scheme(stored_hash)
    if scheme is None:
        return CrackResult(scheme=None, password=None)
    for candidate in wordlist:
        if crypthash.verify(candidate, stored_hash):
            return CrackResult(scheme=scheme, password=candidate)
    return CrackResult(scheme=scheme, password=None)
