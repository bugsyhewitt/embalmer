"""Unit tests for the credential scanner (criterion 4)."""

from __future__ import annotations

from embalmer import creds, crypthash


def test_finds_shadow_password_hash(fake_extracted_tree):
    findings = creds.scan(fake_extracted_tree)
    hashes = [f for f in findings if f.type == "password_hash"]
    assert hashes, "expected at least one shadow password hash finding"
    assert all(f.category == "credential" for f in hashes)
    assert any("etc/shadow" in f.path for f in hashes)


def test_finds_config_credentials(fake_extracted_tree):
    findings = creds.scan(fake_extracted_tree)
    creds_in_conf = [
        f for f in findings
        if f.type == "hardcoded_credential" and "sample.conf" in f.path
    ]
    assert creds_in_conf, "expected hardcoded credentials in sample.conf"
    keys = {f.extra.get("key", "").lower() for f in creds_in_conf}
    assert any("password" in k or "pass" in k for k in keys)
    assert any("api" in k or "key" in k for k in keys)


def test_finds_private_key(fake_extracted_tree):
    findings = creds.scan(fake_extracted_tree)
    keys = [f for f in findings if f.type == "private_key"]
    assert keys, "expected a private-key finding"
    assert any("id_rsa" in f.path for f in keys)


def test_benign_config_not_flagged(fake_extracted_tree):
    findings = creds.scan(fake_extracted_tree)
    # network.conf has hostname/dns only — no password/key/secret/token.
    flagged_network = [f for f in findings if "network.conf" in f.path]
    assert flagged_network == [], "benign config should not produce findings"


def test_every_finding_has_required_keys(fake_extracted_tree):
    findings = creds.scan(fake_extracted_tree)
    assert findings
    for f in findings:
        d = f.to_dict()
        assert d["category"] == "credential"
        assert "path" in d and d["path"]
        assert "type" in d and d["type"]


def test_scan_missing_root_returns_empty(tmp_path):
    assert creds.scan(tmp_path / "does-not-exist") == []


def _write_shadow(tmp_path, lines):
    root = tmp_path / "extract"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "shadow").write_text("".join(line + "\n" for line in lines))
    return root


def test_default_password_is_cracked_and_critical(tmp_path):
    # An account whose password is a known default ("admin") must be reported as
    # a CRITICAL default_password finding with the recovered plaintext.
    weak = crypthash._md5crypt("admin", "$1$abcdefgh$x")
    root = _write_shadow(tmp_path, [f"root:{weak}:19000:0:99999:7:::"])

    findings = creds.scan(root)
    cracked = [f for f in findings if f.type == "default_password"]
    assert len(cracked) == 1
    f = cracked[0]
    assert f.severity == "critical"
    assert f.extra["user"] == "root"
    assert f.extra["password"] == "admin"
    assert f.extra["scheme"] == "md5crypt"
    assert "admin" in f.detail


def test_strong_password_stays_high_password_hash(tmp_path):
    # A hash that does NOT match any default keeps the original high-severity
    # password_hash finding (not promoted, not dropped).
    strong = crypthash._md5crypt("Tr0ub4dor&3xKq!unguessable", "$1$abcdefgh$x")
    root = _write_shadow(tmp_path, [f"svc:{strong}:19000:0:99999:7:::"])

    findings = creds.scan(root)
    cracked = [f for f in findings if f.type == "default_password"]
    hashes = [f for f in findings if f.type == "password_hash"]
    assert cracked == []
    assert len(hashes) == 1
    assert hashes[0].severity == "high"
    assert hashes[0].extra["user"] == "svc"


def test_mixed_shadow_separates_default_from_strong(tmp_path):
    weak = crypthash._md5crypt("vizxv", "$1$Zk3lm9aB$x")
    strong = crypthash._md5crypt("notInTheList999", "$1$abcdefgh$x")
    root = _write_shadow(
        tmp_path,
        [
            f"root:{weak}:19000:0:99999:7:::",
            f"admin:{strong}:19000:0:99999:7:::",
            "daemon:*:19000:0:99999:7:::",  # locked — no finding
        ],
    )

    findings = creds.scan(root)
    by_type = {f.type for f in findings}
    assert "default_password" in by_type
    assert "password_hash" in by_type
    # The locked daemon account contributes no hash finding.
    users = {f.extra.get("user") for f in findings if f.type in ("default_password", "password_hash")}
    assert users == {"root", "admin"}
