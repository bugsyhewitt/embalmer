"""X.509 certificate scanner.

Walks an extracted firmware filesystem for certificate files and surfaces
weak or risky TLS configuration baked into the image. Firmware images
routinely ship long-lived self-signed certs, certs signed with MD5/SHA-1, or
RSA keys too short to be safe — all of which are interesting to an assessor.

Like the credential scanner this is deliberately broad: it parses every file
that *looks* like a certificate and reports what it can read, rather than
trying to be a full PKI validator. Files that fail to parse are skipped
silently (they're almost always not certificates).
"""

from __future__ import annotations

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.hashes import MD5, SHA1
from cryptography.x509.oid import ExtensionOID, NameOID

from .models import Finding

# Extensions that conventionally hold X.509 certificates.
_CERT_SUFFIXES = {".crt", ".pem", ".cer", ".der"}

# Substring that flags a certificate file regardless of extension.
_CERT_NAME_HINT = "certificate"

# Don't try to parse multi-megabyte blobs as certificates.
_MAX_READ_BYTES = 1_000_000

# Minimum acceptable key sizes (bits).
_MIN_RSA_BITS = 2048
_MIN_EC_BITS = 224


def _looks_like_cert(path: Path) -> bool:
    name = path.name.lower()
    if path.suffix.lower() in _CERT_SUFFIXES:
        return True
    return _CERT_NAME_HINT in name


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _load_certs(data: bytes) -> list[x509.Certificate]:
    """Parse one or more certificates out of a blob.

    Tries PEM first (a file may bundle a whole chain), then falls back to a
    single DER certificate. Returns an empty list if nothing parses.
    """
    certs: list[x509.Certificate] = []
    if b"-----BEGIN CERTIFICATE-----" in data:
        try:
            certs = x509.load_pem_x509_certificates(data)
        except Exception:
            certs = []
        if certs:
            return certs
    try:
        certs = [x509.load_der_x509_certificate(data)]
    except Exception:
        certs = []
    return certs


def _cn(name: x509.Name) -> str | None:
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    except Exception:
        return None
    if not attrs:
        return None
    value = attrs[0].value
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def _san_dns_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return []
    except Exception:
        return []
    try:
        return list(ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        return []


def _not_after(cert: x509.Certificate) -> datetime.datetime:
    # not_valid_after_utc is the modern, tz-aware accessor; fall back for
    # older cryptography releases that only expose not_valid_after.
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # pragma: no cover - very old cryptography
        naive = cert.not_valid_after
        return naive.replace(tzinfo=datetime.timezone.utc)


def _weak_algorithm_reason(cert: x509.Certificate) -> str | None:
    """Return a human-readable reason if the cert uses a deprecated algorithm
    or an undersized key, else None."""
    hash_algo = cert.signature_hash_algorithm
    if isinstance(hash_algo, MD5):
        return "MD5 signature algorithm"
    if isinstance(hash_algo, SHA1):
        return "SHA-1 signature algorithm"

    pubkey = cert.public_key()
    if isinstance(pubkey, rsa.RSAPublicKey):
        if pubkey.key_size < _MIN_RSA_BITS:
            return f"RSA key size {pubkey.key_size} bits < {_MIN_RSA_BITS}"
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        if pubkey.key_size < _MIN_EC_BITS:
            return f"EC key size {pubkey.key_size} bits < {_MIN_EC_BITS}"
    return None


def _is_wildcard(subject_cn: str | None, san_names: list[str]) -> bool:
    if subject_cn and "*" in subject_cn:
        return True
    return any("*" in n for n in san_names)


def _finding(
    rel: str,
    cert_type: str,
    severity: str,
    reason: str,
    subject_cn: str | None,
    issuer_cn: str | None,
    expiry: datetime.datetime,
) -> Finding:
    expiry_str = expiry.date().isoformat()
    return Finding(
        category="certificate",
        path=rel,
        type=cert_type,
        detail=reason,
        severity=severity,
        extra={
            "subject_cn": subject_cn,
            "issuer_cn": issuer_cn,
            "expiry": expiry_str,
            "reason": reason,
        },
    )


def scan(extract_root: str | Path) -> list[Finding]:
    """Scan the extracted tree under `extract_root` for risky certificates.

    Each parsed certificate may produce multiple findings (e.g. a cert can be
    both expired and self-signed). Findings carry the cert subject/issuer CN,
    expiry date, and a reason string in their `extra` payload.
    """
    root = Path(extract_root)
    findings: list[Finding] = []

    if not root.exists():
        return findings

    now = datetime.datetime.now(datetime.timezone.utc)

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if not _looks_like_cert(path):
            continue
        try:
            if path.stat().st_size > _MAX_READ_BYTES:
                continue
            data = path.read_bytes()
        except OSError:
            continue

        certs = _load_certs(data)
        if not certs:
            continue

        rel = _rel(path, root)
        for cert in certs:
            subject_cn = _cn(cert.subject)
            issuer_cn = _cn(cert.issuer)
            san_names = _san_dns_names(cert)
            expiry = _not_after(cert)

            # Expired — HIGH.
            if expiry < now:
                findings.append(
                    _finding(
                        rel,
                        "expired_cert",
                        "high",
                        f"certificate expired on {expiry.date().isoformat()}",
                        subject_cn,
                        issuer_cn,
                        expiry,
                    )
                )

            # Self-signed — MEDIUM.
            if cert.issuer == cert.subject:
                findings.append(
                    _finding(
                        rel,
                        "self_signed_cert",
                        "medium",
                        "self-signed certificate (issuer == subject)",
                        subject_cn,
                        issuer_cn,
                        expiry,
                    )
                )

            # Weak algorithm / undersized key — MEDIUM.
            weak = _weak_algorithm_reason(cert)
            if weak is not None:
                findings.append(
                    _finding(
                        rel,
                        "weak_algorithm_cert",
                        "medium",
                        weak,
                        subject_cn,
                        issuer_cn,
                        expiry,
                    )
                )

            # Wildcard — INFO.
            if _is_wildcard(subject_cn, san_names):
                findings.append(
                    _finding(
                        rel,
                        "wildcard_cert",
                        "info",
                        "wildcard certificate (CN or SAN contains '*')",
                        subject_cn,
                        issuer_cn,
                        expiry,
                    )
                )

    return findings
