"""Unit tests for the X.509 certificate scanner.

Generates real PEM/DER certificate bytes with `cryptography` so the scanner
runs against genuine artifacts rather than mocks (Article IX:
integration-first — real certs over stubs).
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from embalmer import certs

_NOW = datetime.datetime.now(datetime.timezone.utc)

# A real SHA-1-signed, self-signed certificate (CN=legacy.example.com).
# Embedded as a constant because modern OpenSSL builds refuse to *sign* new
# certs with SHA-1, but firmware images routinely still ship them — and
# `cryptography` parses them fine. This is exactly the legacy artifact the
# weak-algorithm check exists to catch.
_SHA1_CERT_PEM = b"""-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIUdIuWodSa0DdOQHeSaVw7YgTXZccwDQYJKoZIhvcNAQEF
BQAwHTEbMBkGA1UEAwwSbGVnYWN5LmV4YW1wbGUuY29tMB4XDTI2MDUyNzAwMTcz
NFoXDTI3MDUyNzAwMTczNFowHTEbMBkGA1UEAwwSbGVnYWN5LmV4YW1wbGUuY29t
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwZ79XFA8KtH9x9yw8a18
auY7PnmlR6EVQ//cabCOG9P6pske1goy0FDvEKjEL9vb1GMVFOHHLUkE8rCmvkLf
rVgzlzL9oM6GU74zT0jmks1ii5baSvSCj6x6UyNrcr6kf4I7E6Bystki0J1IMtt1
OfdQTj1IVJpynR1MOq3xPrNiyiwoCsch66zcTeQCSwqb1UxN+AybDSWrvintgPPc
NeGWQfnQQMyczqobmOtEM70txaLxZTdRq5p6BaCrCaj0SMxG4bjGpZcFYDMmOKT6
+Z8Dhe7ugE2TrjyuoXs/2TcX6nE2Te2Hamk5tQph8d3yJ7FTyIuG5LMsY/dW2t3E
lQIDAQABo1MwUTAdBgNVHQ4EFgQUspoYYIrnH4S7CTdR0tfwdhOGM7MwHwYDVR0j
BBgwFoAUspoYYIrnH4S7CTdR0tfwdhOGM7MwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQUFAAOCAQEALQfy0giJz+QQqBCsT1BPthRouTQKmF0/cwkuhCt79zz8
4X0FLMLt8bSpqinvyPx9zmzIx5LXb9G/aaXwoefbRmk5rvixfxl6huaTe3Pn9tLg
f6tz5Hlcby/WVhThQ5IFnrj+aYxr8P5rRHVg4vUfcLyQIc8useS3QPyCIr6LS6fz
EMIxS9e0YDdT7GkFQaaqgErQb7WN+TYgLpbKFzwepu+rFF46U1/XVD6YdOd2koII
BIr/7u9DOpUAfE+4l7Sa7XaJHfzlbzm734j+5JO/I/5M+RTJhQK7KHV1LW3fcORo
QMVtWsVTyCsyjksOSBzBjI2eHCgmf0Q51f2M0QDbHg==
-----END CERTIFICATE-----
"""


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _build_cert(
    *,
    subject_cn: str,
    issuer_cn: str | None = None,
    key=None,
    sign_hash=None,
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
    san: list[str] | None = None,
) -> tuple[x509.Certificate, object]:
    """Build a signed X.509 certificate.

    If `issuer_cn` is None the cert is self-signed (issuer == subject).
    """
    if key is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if sign_hash is None:
        sign_hash = hashes.SHA256()
    if not_before is None:
        not_before = _NOW - datetime.timedelta(days=1)
    if not_after is None:
        not_after = _NOW + datetime.timedelta(days=365)

    subject = _name(subject_cn)
    issuer = _name(issuer_cn) if issuer_cn is not None else subject

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]),
            critical=False,
        )
    cert = builder.sign(private_key=key, algorithm=sign_hash)
    return cert, key


def _write_pem(path: Path, cert: x509.Certificate) -> None:
    from cryptography.hazmat.primitives.serialization import Encoding

    path.write_bytes(cert.public_bytes(Encoding.PEM))


def _write_der(path: Path, cert: x509.Certificate) -> None:
    from cryptography.hazmat.primitives.serialization import Encoding

    path.write_bytes(cert.public_bytes(Encoding.DER))


@pytest.fixture
def cert_tree(tmp_path: Path) -> Path:
    """An extracted-firmware layout populated with certificate files exercising
    every finding type the scanner emits."""
    root = tmp_path / "extract"
    etc = root / "etc" / "ssl"
    etc.mkdir(parents=True)

    # Self-signed, healthy cert (MEDIUM: self-signed only).
    self_signed, _ = _build_cert(subject_cn="device.local", issuer_cn=None)
    _write_pem(etc / "self_signed.pem", self_signed)

    # CA-signed, expired (HIGH: expired). Not self-signed.
    expired, _ = _build_cert(
        subject_cn="old.example.com",
        issuer_cn="Example CA",
        not_before=_NOW - datetime.timedelta(days=800),
        not_after=_NOW - datetime.timedelta(days=10),
    )
    _write_pem(etc / "expired.crt", expired)

    # SHA-1 signed cert (MEDIUM: weak algorithm) — embedded real artifact.
    (etc / "sha1.cer").write_bytes(_SHA1_CERT_PEM)

    # 1024-bit RSA, CA-signed (MEDIUM: weak key). Suppress the small-key
    # warning the library raises for signing with <2048-bit keys.
    import warnings

    weak_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        weak_rsa, _ = _build_cert(
            subject_cn="weakrsa.example.com",
            issuer_cn="Weak CA",
            key=weak_key,
        )
    _write_pem(etc / "weak_rsa.pem", weak_rsa)

    # Wildcard via CN, CA-signed, strong key (INFO: wildcard).
    wildcard, _ = _build_cert(
        subject_cn="*.wildcard.example.com",
        issuer_cn="Wildcard CA",
    )
    _write_pem(etc / "wildcard.crt", wildcard)

    # Wildcard via SAN, CA-signed (INFO: wildcard) — also DER-encoded and
    # named with no recognized extension but with 'certificate' in the name.
    wildcard_san, _ = _build_cert(
        subject_cn="api.example.com",
        issuer_cn="SAN CA",
        san=["*.api.example.com"],
    )
    _write_der(etc / "san_wildcard_certificate", wildcard_san)

    # A non-certificate file with a cert-y extension — must be skipped.
    (etc / "notes.pem").write_bytes(b"this is not a certificate\n")

    # A wholly unrelated file — must be ignored.
    (root / "etc" / "hostname").write_text("router\n")

    return root


def test_self_signed_flagged(cert_tree):
    findings = certs.scan(cert_tree)
    selfs = [f for f in findings if f.type == "self_signed_cert"]
    assert selfs, "expected a self-signed finding"
    f = next(f for f in selfs if "self_signed.pem" in f.path)
    assert f.severity == "medium"
    assert f.extra["subject_cn"] == "device.local"
    assert f.extra["issuer_cn"] == "device.local"


def test_expired_flagged(cert_tree):
    findings = certs.scan(cert_tree)
    expired = [f for f in findings if f.type == "expired_cert"]
    assert expired, "expected an expired finding"
    f = next(f for f in expired if "expired.crt" in f.path)
    assert f.severity == "high"
    assert "expired" in f.extra["reason"]
    # Expired cert here is CA-signed, so it should NOT also be self-signed.
    self_for_expired = [
        x for x in findings if "expired.crt" in x.path and x.type == "self_signed_cert"
    ]
    assert self_for_expired == []


def test_sha1_flagged(cert_tree):
    findings = certs.scan(cert_tree)
    weak = [
        f
        for f in findings
        if f.type == "weak_algorithm_cert" and "sha1.cer" in f.path
    ]
    assert weak, "expected a SHA-1 weak-algorithm finding"
    assert weak[0].severity == "medium"
    assert "SHA-1" in weak[0].extra["reason"]


def test_weak_rsa_key_flagged(cert_tree):
    findings = certs.scan(cert_tree)
    weak = [
        f
        for f in findings
        if f.type == "weak_algorithm_cert" and "weak_rsa.pem" in f.path
    ]
    assert weak, "expected a weak RSA key finding"
    assert weak[0].severity == "medium"
    assert "RSA key size 1024" in weak[0].extra["reason"]


def test_wildcard_cn_flagged(cert_tree):
    findings = certs.scan(cert_tree)
    wild = [
        f for f in findings if f.type == "wildcard_cert" and "wildcard.crt" in f.path
    ]
    assert wild, "expected a wildcard (CN) finding"
    assert wild[0].severity == "info"


def test_wildcard_san_and_der_parsing(cert_tree):
    findings = certs.scan(cert_tree)
    wild = [
        f
        for f in findings
        if f.type == "wildcard_cert" and "san_wildcard_certificate" in f.path
    ]
    assert wild, "expected wildcard finding from a DER cert matched by name hint"
    assert wild[0].severity == "info"


def test_non_certificate_pem_skipped(cert_tree):
    findings = certs.scan(cert_tree)
    assert all("notes.pem" not in f.path for f in findings)


def test_findings_have_required_shape(cert_tree):
    findings = certs.scan(cert_tree)
    assert findings
    for f in findings:
        d = f.to_dict()
        assert d["category"] == "certificate"
        assert d["path"]
        assert d["type"]
        assert d["severity"] in {"high", "medium", "info"}
        # Enriched fields surfaced via extra.
        assert "expiry" in d
        assert "reason" in d
        assert "subject_cn" in d
        assert "issuer_cn" in d


def test_ec_curve_too_small_flagged(tmp_path: Path):
    """A SECP192R1 (192-bit) EC cert is below the 224-bit floor."""
    root = tmp_path / "extract"
    root.mkdir()
    key = ec.generate_private_key(ec.SECP192R1())
    cert, _ = _build_cert(
        subject_cn="ec.example.com",
        issuer_cn="EC CA",
        key=key,
        sign_hash=hashes.SHA256(),
    )
    _write_pem(root / "ec.pem", cert)

    findings = certs.scan(root)
    weak = [f for f in findings if f.type == "weak_algorithm_cert"]
    assert weak, "expected a weak EC key finding"
    assert "EC key size 192" in weak[0].extra["reason"]


def test_healthy_cert_produces_no_findings(tmp_path: Path):
    """A modern CA-signed, non-wildcard, strong, unexpired cert is clean."""
    root = tmp_path / "extract"
    root.mkdir()
    cert, _ = _build_cert(subject_cn="good.example.com", issuer_cn="Good CA")
    _write_pem(root / "good.pem", cert)
    assert certs.scan(root) == []


def test_scan_missing_root_returns_empty(tmp_path: Path):
    assert certs.scan(tmp_path / "does-not-exist") == []
