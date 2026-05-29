"""Tests for crypt(3) hash verification and default-credential cracking.

The crypt hashes used here are generated at test time by ``openssl passwd``
where available (the authoritative cross-check that embalmer's pure-Python
crypt(3) reimplementation is byte-for-byte correct), and supplemented with
hard-coded reference vectors so the suite still proves correctness on a machine
without openssl.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from embalmer import crypthash, defaultcreds

_HAS_OPENSSL = shutil.which("openssl") is not None


def _openssl_passwd(flag: str, salt: str, password: str) -> str:
    return (
        subprocess.check_output(["openssl", "passwd", flag, "-salt", salt, password])
        .decode()
        .strip()
    )


# --------------------------------------------------------------------------- #
# crypthash: scheme identification
# --------------------------------------------------------------------------- #


def test_identify_scheme_md5():
    assert crypthash.identify_scheme("$1$salt$qJH7.N4xYta3aEG/dfqo/0") == "md5crypt"


def test_identify_scheme_sha256():
    assert crypthash.identify_scheme("$5$saltstring$abc") == "sha256crypt"


def test_identify_scheme_sha512():
    assert crypthash.identify_scheme("$6$saltstring$abc") == "sha512crypt"


@pytest.mark.parametrize(
    "stored",
    [
        "",  # empty
        "*",  # locked
        "!",  # locked
        "!!",  # never set
        "x",  # password in another file
        "$2y$10$abcdefghijklmnopqrstuv",  # bcrypt — deliberately unsupported
        "$y$j9T$abcdef",  # yescrypt — deliberately unsupported
        "abJnggxhB/yWI",  # 13-char DES — out of scope, must not be claimed
    ],
)
def test_identify_scheme_rejects_unsupported(stored):
    assert crypthash.identify_scheme(stored) is None


# --------------------------------------------------------------------------- #
# crypthash: verification against reference vectors
# --------------------------------------------------------------------------- #

# Reference vectors from the canonical algorithm definitions / openssl, so the
# suite proves correctness even without openssl on the box.
_REFERENCE_VECTORS = [
    ("password", "$1$salt$qJH7.N4xYta3aEG/dfqo/0"),
    ("Hello world!", "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"),
    (
        "Hello world!",
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJu"
        "esI68u4OTLiBFdcbYEdFCoEOfaS35inz1",
    ),
    (
        "Hello world!",
        "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2."
        "opqey6IcA",
    ),
]


@pytest.mark.parametrize("password,stored", _REFERENCE_VECTORS)
def test_verify_reference_vectors(password, stored):
    assert crypthash.verify(password, stored) is True


@pytest.mark.parametrize("password,stored", _REFERENCE_VECTORS)
def test_verify_rejects_wrong_password(password, stored):
    assert crypthash.verify(password + "x", stored) is False


def test_verify_unsupported_hash_is_false():
    # A bcrypt hash is identified as unsupported and never verifies.
    assert crypthash.verify("password", "$2y$10$abcdefghijklmnopqrstuv") is False
    assert crypthash.verify("anything", "*") is False


@pytest.mark.skipif(not _HAS_OPENSSL, reason="openssl not available")
@pytest.mark.parametrize("flag,scheme", [("-1", "md5crypt"), ("-5", "sha256crypt"), ("-6", "sha512crypt")])
@pytest.mark.parametrize("password", ["admin", "Hello world!", "1234", "p@ss w0rd"])
def test_verify_matches_openssl(flag, scheme, password):
    stored = _openssl_passwd(flag, "saltsalt", password)
    assert crypthash.identify_scheme(stored) == scheme
    assert crypthash.verify(password, stored) is True
    assert crypthash.verify(password + "_no", stored) is False


# --------------------------------------------------------------------------- #
# defaultcreds: cracking against the wordlist
# --------------------------------------------------------------------------- #


def test_crack_finds_default_password():
    # md5crypt hash of "admin" (a wordlist entry) computed by our own verified
    # implementation, then cracked back.
    stored = crypthash._md5crypt("admin", "$1$abcdefgh$x")
    result = defaultcreds.crack(stored)
    assert result.cracked is True
    assert result.password == "admin"
    assert result.scheme == "md5crypt"


def test_crack_finds_mirai_dictionary_password():
    stored = crypthash._md5crypt("vizxv", "$1$Zk3lm9aB$x")
    result = defaultcreds.crack(stored)
    assert result.cracked is True
    assert result.password == "vizxv"


def test_crack_empty_password():
    stored = crypthash._md5crypt("", "$1$emptyslt$x")
    result = defaultcreds.crack(stored)
    assert result.cracked is True
    assert result.password == ""


def test_crack_strong_password_not_cracked():
    stored = crypthash._md5crypt("Tr0ub4dor&3xKq!nope", "$1$abcdefgh$x")
    result = defaultcreds.crack(stored)
    assert result.cracked is False
    assert result.password is None
    assert result.scheme == "md5crypt"


def test_crack_unsupported_hash():
    result = defaultcreds.crack("$2y$10$abcdefghijklmnopqrstuv")
    assert result.cracked is False
    assert result.scheme is None


def test_crack_respects_custom_wordlist():
    stored = crypthash._md5crypt("admin", "$1$abcdefgh$x")
    # "admin" is not in this custom list, so it must not crack.
    result = defaultcreds.crack(stored, wordlist=("root", "1234"))
    assert result.cracked is False


def test_wordlist_is_high_signal_and_includes_mirai():
    wl = defaultcreds.DEFAULT_WORDLIST
    # Sanity: the wordlist is small and curated, not a megabyte dictionary.
    assert 50 <= len(wl) <= 200
    # Must contain the universal defaults and the Mirai dictionary anchors.
    for must in ("admin", "root", "password", "1234", "vizxv", "xc3511", ""):
        assert must in wl
