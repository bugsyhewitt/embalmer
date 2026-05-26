"""Credential scanner.

Walks an extracted firmware filesystem and surfaces likely hardcoded
credentials, password hashes, and private keys. This is deliberately a broad,
pattern-based scan (the same fast-and-broad philosophy as the blight handoff)
rather than a precise secret-detection engine — v0.1 only needs to reliably
catch the planted artifacts in the bundled fixture and obvious real-world
equivalents.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import Finding

# Files whose entire purpose is storing password hashes.
_SHADOW_NAMES = {"shadow", "shadow-", "master.passwd"}

# A populated /etc/shadow line: user:HASH:... where HASH starts with $id$.
_SHADOW_HASH_RE = re.compile(r"^[^:]+:(\$[0-9a-z]{1,3}\$[^:]+):", re.MULTILINE)

# key=value style credentials in config files.
_CONFIG_CRED_RE = re.compile(
    r"(?im)^\s*([a-z0-9_.\-]*"
    r"(?:pass(?:word|wd)?|secret|api[_-]?key|access[_-]?key|token|priv[_-]?key))"
    r"\s*[=:]\s*(\S+)"
)

# Inline private-key PEM blocks.
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")

# Filenames that are private keys regardless of content sniffing.
_KEY_FILENAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "server.key", "private.key"}

# Skip obviously-binary or huge files when reading text.
_MAX_READ_BYTES = 1_000_000


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_READ_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    # Heuristic: treat NUL-containing blobs as binary, skip them.
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        return None


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def scan(extract_root: str | Path) -> list[Finding]:
    """Scan the extracted tree under `extract_root` for credentials."""
    root = Path(extract_root)
    findings: list[Finding] = []

    if not root.exists():
        return findings

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue

        rel = _rel(path, root)
        name = path.name

        # Private key by filename — flag regardless of readability.
        if name in _KEY_FILENAMES:
            findings.append(
                Finding(
                    category="credential",
                    path=rel,
                    type="private_key",
                    detail=f"private key file by name: {name}",
                    severity="high",
                )
            )

        text = _read_text(path)
        if text is None:
            continue

        # /etc/shadow style password hashes.
        if name in _SHADOW_NAMES:
            for match in _SHADOW_HASH_RE.finditer(text):
                findings.append(
                    Finding(
                        category="credential",
                        path=rel,
                        type="password_hash",
                        detail=f"shadow password hash: {match.group(1)[:16]}...",
                        severity="high",
                    )
                )

        # Inline PEM private keys (any file).
        if _PRIVATE_KEY_RE.search(text):
            # Avoid double-reporting a key file already flagged by name.
            already = any(
                f.path == rel and f.type == "private_key" for f in findings
            )
            if not already:
                findings.append(
                    Finding(
                        category="credential",
                        path=rel,
                        type="private_key",
                        detail="inline PEM PRIVATE KEY block",
                        severity="high",
                    )
                )

        # key=value credentials in config-like files.
        for match in _CONFIG_CRED_RE.finditer(text):
            key = match.group(1)
            value = match.group(2)
            # Skip empty / obviously-templated values.
            if not value or value in {'""', "''", "x", "*"}:
                continue
            findings.append(
                Finding(
                    category="credential",
                    path=rel,
                    type="hardcoded_credential",
                    detail=f"{key}=<redacted len {len(value)}>",
                    severity="medium",
                    extra={"key": key},
                )
            )

    return findings
