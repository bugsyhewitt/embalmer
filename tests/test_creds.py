"""Unit tests for the credential scanner (criterion 4)."""

from __future__ import annotations

from embalmer import creds


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
