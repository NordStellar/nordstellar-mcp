#!/usr/bin/env python3
"""Check dependency licenses with naive dual-license support.

Reads ``pip-licenses --format=json``, splits each license cell on ``;`` (pip
joins classifiers) and on ``OR`` (case-insensitive), then applies the same
substring / exact rules as ``[tool.license-clause-check]`` to *each* clause.
Fails if *any* clause matches a ``fail-on`` pattern (e.g. ``GPL-2.0 OR MIT``).

Does not parse full SPDX (no ``AND``, ``WITH``, parentheses). For that, use a
SPDX-aware tool instead.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

_OR_SPLIT = re.compile(r"\s+OR\s+", re.IGNORECASE)


def _load_tool_section(pyproject: Path, name: str) -> dict:
    raw = pyproject.read_bytes()
    if sys.version_info >= (3, 11):
        import tomllib

        data = tomllib.loads(raw.decode())
        return data.get("tool", {}).get(name, {})
    # Python 3.10: minimal single-table parse (no multiline values).
    text = raw.decode()
    header = f"[tool.{name}]"
    if header not in text:
        return {}
    start = text.index(header) + len(header)
    rest = text[start:]
    end = re.search(r"\n\[", rest)
    block = rest if end is None else rest[: end.start()]
    section: dict[str, object] = {}
    for line in block.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if val == "true":
            section[key] = True
        elif val == "false":
            section[key] = False
        else:
            try:
                section[key] = json.loads(val)
            except json.JSONDecodeError:
                raise SystemExit(f"Cannot parse value for {key!r} in {header}") from None
    return section


def _ignore_packages(lc: dict, pl: dict) -> list[str]:
    ips = lc.get("ignore-packages")
    if isinstance(ips, list) and ips:
        return [str(x) for x in ips]
    ips = pl.get("ignore-packages")
    if isinstance(ips, list):
        return [str(x) for x in ips]
    return []


def atomic_clauses(license_text: str) -> list[str]:
    stripped = license_text.strip() if license_text else ""
    if not stripped or stripped.upper() == "UNKNOWN":
        return ["UNKNOWN"]
    atoms: list[str] = []
    for semi_piece in re.split(r"\s*;\s*", stripped):
        s = semi_piece.strip()
        if not s:
            continue
        for or_piece in _OR_SPLIT.split(s):
            p = or_piece.strip()
            if p:
                atoms.append(p)
    return atoms or ["UNKNOWN"]


def clause_matches(
    clause: str, patterns: list[str], *, partial_match: bool
) -> str | None:
    c = clause
    for raw in patterns:
        pat = raw.strip()
        if not pat:
            continue
        if partial_match:
            if pat.lower() in c.lower():
                return pat
        else:
            if pat.lower() == c.lower():
                return pat
    return None


def main() -> int:
    repo = Path.cwd()
    pyproject = repo / "pyproject.toml"
    if not pyproject.is_file():
        print("Expected pyproject.toml in current directory", file=sys.stderr)
        return 1

    lc_cfg = _load_tool_section(pyproject, "license-clause-check")
    pl_cfg = _load_tool_section(pyproject, "pip-licenses")

    fail_raw = lc_cfg.get("fail-on")
    if not isinstance(fail_raw, str) or not fail_raw.strip():
        print("[tool.license-clause-check].fail-on is missing or empty", file=sys.stderr)
        return 1
    patterns = [p for p in (x.strip() for x in fail_raw.split(";")) if p]

    partial = bool(lc_cfg.get("partial-match", True))

    ignores = _ignore_packages(lc_cfg, pl_cfg)
    ignore_norm = {n.lower().replace("_", "-") for n in ignores}

    cmd = [
        sys.executable,
        "-m",
        "piplicenses",
        "--format=json",
        "--from=mixed",
    ]
    if ignores:
        cmd.append("--ignore-packages")
        cmd.extend(ignores)

    proc = subprocess.run(
        cmd,
        cwd=repo,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(proc.stderr or proc.stdout, file=sys.stderr)
        return proc.returncode

    try:
        rows = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        print(f"Invalid JSON from pip-licenses: {e}", file=sys.stderr)
        return 1

    failed = False
    for row in rows:
        name = str(row.get("Name", ""))
        version = str(row.get("Version", ""))
        lic = str(row.get("License", "UNKNOWN"))

        pkg_key = name.lower().replace("_", "-")
        if pkg_key in ignore_norm:
            continue

        for clause in atomic_clauses(lic):
            matched = clause_matches(clause, patterns, partial_match=partial)
            if matched is not None:
                failed = True
                print(
                    f"{name}:{version}: clause {clause!r} matched forbidden {matched!r} "
                    f"(from license {lic!r})",
                    file=sys.stderr,
                )

    if failed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
