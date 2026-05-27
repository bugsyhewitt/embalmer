"""Report rendering: JSON and markdown.

Both formats render the exact same `Report` object so they can never disagree.
JSON is a direct serialization; markdown is a human-readable summary that
exposes the same extraction tree, credential findings, and binary findings.
"""

from __future__ import annotations

import json
from typing import Any

from .models import Report


def to_json(report: Report, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, sort_keys=False)


def _render_tree(tree: dict[str, Any], prefix: str = "") -> list[str]:
    lines: list[str] = []
    names = list(tree.keys())
    for idx, name in enumerate(names):
        node = tree[name]
        is_last = idx == len(names) - 1
        branch = "└── " if is_last else "├── "
        child_prefix = prefix + ("    " if is_last else "│   ")
        if isinstance(node, dict) and node.get("_type") == "file":
            lines.append(f"{prefix}{branch}{name} ({node.get('size', 0)} B)")
        elif isinstance(node, dict) and node.get("_type") == "symlink":
            lines.append(f"{prefix}{branch}{name} -> {node.get('target', '?')}")
        elif isinstance(node, dict):
            lines.append(f"{prefix}{branch}{name}/")
            lines.extend(_render_tree(node, child_prefix))
        else:
            lines.append(f"{prefix}{branch}{name}")
    return lines


def to_markdown(report: Report) -> str:
    data = report.to_dict()
    out: list[str] = []
    out.append(f"# Firmware Audit Report: `{data['firmware']}`")
    out.append("")
    out.append(f"**Checks run:** {', '.join(data['checks'])}")
    out.append("")

    if "extraction" in data:
        ext = data["extraction"]
        out.append("## Extraction")
        out.append("")
        out.append(f"- **Files extracted:** {ext['file_count']}")
        out.append(f"- **Extraction time:** {ext['extraction_time_ms']} ms")
        out.append(f"- **Extract root:** `{ext['extract_root']}`")
        out.append("")
        out.append("### Extraction tree")
        out.append("")
        out.append("```")
        tree_lines = _render_tree(ext["extraction_tree"])
        out.extend(tree_lines if tree_lines else ["(empty)"])
        out.append("```")
        out.append("")

    if "credentials" in data:
        creds = data["credentials"]
        out.append("## Credential findings")
        out.append("")
        if not creds:
            out.append("_No credential findings._")
        else:
            out.append("| Severity | Type | Path | Detail |")
            out.append("|---|---|---|---|")
            for f in creds:
                out.append(
                    f"| {f['severity']} | {f['type']} | `{f['path']}` | {f['detail']} |"
                )
        out.append("")

    if "certificates" in data:
        certs = data["certificates"]
        out.append("## Certificate findings")
        out.append("")
        if not certs:
            out.append("_No certificate findings._")
        else:
            out.append(
                "| Severity | Type | Path | Subject CN | Issuer CN | Expiry | Reason |"
            )
            out.append("|---|---|---|---|---|---|---|")
            for f in certs:
                out.append(
                    f"| {f['severity']} | {f['type']} | `{f['path']}` "
                    f"| {f.get('subject_cn') or '-'} "
                    f"| {f.get('issuer_cn') or '-'} "
                    f"| {f.get('expiry') or '-'} "
                    f"| {f.get('reason') or f['detail']} |"
                )
        out.append("")

    if "binaries" in data:
        bins = data["binaries"]
        out.append("## Binary findings (via blight)")
        out.append("")
        if not bins:
            out.append("_No binary findings._")
        else:
            out.append("| Severity | Type | Path | Detail |")
            out.append("|---|---|---|---|")
            for f in bins:
                out.append(
                    f"| {f['severity']} | {f['type']} | `{f['path']}` | {f['detail']} |"
                )
        out.append("")

    return "\n".join(out)


def render(report: Report, fmt: str) -> str:
    if fmt == "json":
        return to_json(report)
    if fmt == "md":
        return to_markdown(report)
    raise ValueError(f"unknown format: {fmt!r}")
