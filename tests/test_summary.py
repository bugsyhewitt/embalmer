"""Unit tests for finding deduplication, grouping, and the summary block."""

from __future__ import annotations

import json

from embalmer.models import Finding, Report
from embalmer.report import to_json, to_markdown
from embalmer.summary import (
    Summary,
    build_summary,
    deduplicate,
    group_binaries,
    postprocess,
)


def _cred(path: str, key: str = "admin_password", sev: str = "medium") -> Finding:
    return Finding(
        category="credential",
        path=path,
        type="hardcoded_credential",
        detail=f"{key}=<redacted len 12>",
        severity=sev,
        extra={"key": key},
    )


def _binary(path: str, cwe: str = "CWE-120", func: str = "strcpy") -> Finding:
    return Finding(
        category="binary",
        path=path,
        type=cwe,
        detail="overflow",
        severity="high",
        extra={"function": func},
    )


# --------------------------------------------------------------------------- #
# deduplicate
# --------------------------------------------------------------------------- #


def test_dedup_collapses_identical_findings_across_paths():
    findings = [_cred("etc/a.conf"), _cred("etc/b.conf"), _cred("etc/c.conf")]
    out = deduplicate(findings)
    assert len(out) == 1
    assert out[0].extra["count"] == 3
    assert out[0].extra["paths"] == ["etc/a.conf", "etc/b.conf", "etc/c.conf"]
    # The survivor keeps its own first path.
    assert out[0].path == "etc/a.conf"


def test_dedup_keeps_distinct_keys_separate():
    findings = [
        _cred("etc/a.conf", key="admin_password"),
        _cred("etc/a.conf", key="api_key"),
    ]
    out = deduplicate(findings)
    assert len(out) == 2


def test_dedup_keeps_distinct_severity_separate():
    findings = [
        _cred("etc/a.conf", sev="high"),
        _cred("etc/b.conf", sev="medium"),
    ]
    out = deduplicate(findings)
    assert len(out) == 2


def test_dedup_singleton_still_gets_count_and_paths():
    out = deduplicate([_cred("etc/only.conf")])
    assert out[0].extra["count"] == 1
    assert out[0].extra["paths"] == ["etc/only.conf"]


def test_dedup_paths_are_sorted_and_unique():
    findings = [_cred("z.conf"), _cred("a.conf"), _cred("a.conf")]
    out = deduplicate(findings)
    assert out[0].extra["count"] == 3  # raw occurrences counted
    assert out[0].extra["paths"] == ["a.conf", "z.conf"]  # sorted + deduped


def test_dedup_preserves_first_appearance_order():
    findings = [
        _cred("a", key="k1"),
        _cred("b", key="k2"),
        _cred("c", key="k1"),
    ]
    out = deduplicate(findings)
    assert [f.extra["key"] for f in out] == ["k1", "k2"]


def test_dedup_binary_distinguishes_by_function():
    findings = [
        _binary("bin/x", func="strcpy"),
        _binary("bin/y", func="strcpy"),
        _binary("bin/z", func="memcpy"),
    ]
    out = deduplicate(findings)
    # Two distinct functions -> two findings; first collapses two paths.
    assert len(out) == 2
    assert out[0].extra["count"] == 2
    assert out[1].extra["count"] == 1


def test_dedup_empty_list():
    assert deduplicate([]) == []


# --------------------------------------------------------------------------- #
# group_binaries
# --------------------------------------------------------------------------- #


def test_group_binaries_clusters_by_path():
    findings = [
        _binary("bin/busybox", cwe="CWE-120"),
        _binary("bin/busybox", cwe="CWE-134", func="printf"),
        _binary("lib/libc.so", cwe="CWE-120"),
    ]
    groups = group_binaries(findings)
    assert len(groups) == 2
    assert groups[0].path == "bin/busybox"
    assert groups[0].finding_count if hasattr(groups[0], "finding_count") else True
    assert len(groups[0].findings) == 2
    assert len(groups[1].findings) == 1


def test_group_binaries_ignores_non_binary():
    findings = [_cred("etc/a.conf"), _binary("bin/x")]
    groups = group_binaries(findings)
    assert len(groups) == 1
    assert groups[0].path == "bin/x"


def test_group_binaries_to_dict_shape():
    groups = group_binaries([_binary("bin/x"), _binary("bin/x", cwe="CWE-134")])
    d = groups[0].to_dict()
    assert d["path"] == "bin/x"
    assert d["finding_count"] == 2
    assert len(d["findings"]) == 2


# --------------------------------------------------------------------------- #
# build_summary
# --------------------------------------------------------------------------- #


def test_summary_counts_by_severity_and_category():
    report = Report(
        firmware="fw.bin",
        checks=["creds", "binaries"],
        credentials=[_cred("a", sev="high"), _cred("b", key="api_key", sev="medium")],
        binaries=[_binary("bin/x", func="strcpy"), _binary("bin/y", func="memcpy")],
    )
    summary = build_summary(report)
    assert summary.total == 4
    assert summary.by_severity == {"high": 3, "medium": 1}
    assert summary.by_category == {"binary": 2, "credential": 2}


def test_summary_severity_order_is_canonical():
    report = Report(
        firmware="fw.bin",
        checks=["creds"],
        credentials=[
            _cred("a", sev="info"),
            _cred("b", key="k2", sev="critical"),
            _cred("c", key="k3", sev="medium"),
        ],
    )
    summary = build_summary(report)
    assert list(summary.by_severity.keys()) == ["critical", "medium", "info"]


def test_summary_unknown_severity_bucketed_as_other():
    report = Report(
        firmware="fw.bin",
        checks=["creds"],
        credentials=[_cred("a", sev="bizarre")],
    )
    summary = build_summary(report)
    assert summary.by_severity == {"other": 1}


def test_summary_empty_when_no_findings():
    report = Report(firmware="fw.bin", checks=["creds"], credentials=[])
    summary = build_summary(report)
    assert summary.total == 0
    assert summary.by_severity == {}
    assert summary.by_category == {}


# --------------------------------------------------------------------------- #
# postprocess (integration of the three steps)
# --------------------------------------------------------------------------- #


def test_postprocess_dedups_groups_and_summarizes():
    report = Report(
        firmware="fw.bin",
        checks=["creds", "binaries"],
        credentials=[_cred("etc/a.conf"), _cred("etc/b.conf")],  # same key -> dedup
        binaries=[_binary("bin/x"), _binary("bin/y")],  # same func -> dedup
    )
    postprocess(report)

    # Credentials collapsed to one with count 2.
    assert len(report.credentials) == 1
    assert report.credentials[0].extra["count"] == 2

    # Binaries collapsed to one (same function) with count 2.
    assert len(report.binaries) == 1
    assert report.binaries[0].extra["count"] == 2

    # Grouping reflects the (post-dedup) surviving binary finding.
    assert report.binary_groups is not None
    assert len(report.binary_groups) == 1

    # Summary present and counts distinct findings, not collapsed copies.
    assert report.summary is not None
    assert report.summary.total == 2


def test_postprocess_skips_sections_that_did_not_run():
    report = Report(firmware="fw.bin", checks=["extract"])
    postprocess(report)
    assert report.credentials is None
    assert report.certificates is None
    assert report.binaries is None
    assert report.binary_groups is None
    # No finding-bearing check ran -> no summary.
    assert report.summary is None


def test_postprocess_summary_present_for_empty_creds_run():
    report = Report(firmware="fw.bin", checks=["creds"], credentials=[])
    postprocess(report)
    assert report.summary is not None
    assert report.summary.total == 0


def test_postprocess_collapses_to_single_survivor():
    report = Report(
        firmware="fw.bin",
        checks=["creds"],
        credentials=[_cred("etc/a.conf"), _cred("etc/b.conf")],
    )
    postprocess(report)
    # Two duplicate inputs collapse to one survivor carrying count 2.
    assert len(report.credentials) == 1
    assert report.credentials[0].extra["count"] == 2


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #


def test_summary_serialized_in_json():
    report = Report(
        firmware="fw.bin",
        checks=["creds", "binaries"],
        credentials=[_cred("etc/a.conf"), _cred("etc/b.conf")],
        binaries=[_binary("bin/x")],
    )
    postprocess(report)
    parsed = json.loads(to_json(report))
    assert parsed["summary"]["total"] == 2
    assert parsed["summary"]["by_category"]["credential"] == 1
    # Deduped credential carries count + paths in JSON.
    cred = parsed["credentials"][0]
    assert cred["count"] == 2
    assert cred["paths"] == ["etc/a.conf", "etc/b.conf"]
    # Per-binary grouping serialized.
    assert parsed["binary_groups"][0]["path"] == "bin/x"


def test_summary_rendered_in_markdown():
    report = Report(
        firmware="fw.bin",
        checks=["creds", "binaries"],
        credentials=[_cred("etc/a.conf"), _cred("etc/b.conf")],
        binaries=[_binary("bin/x")],
    )
    postprocess(report)
    md = to_markdown(report)
    assert "## Summary" in md
    assert "Total findings:" in md
    assert "Binary findings by binary" in md
    assert "bin/x" in md


def test_markdown_no_summary_when_absent():
    report = Report(firmware="fw.bin", checks=["extract"])
    md = to_markdown(report)
    assert "## Summary" not in md
