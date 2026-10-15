"""
Which names an Arch pkgbase goes by in the proxy ecosystems.

Debian and Alpine key their records by source package, which usually
matches Arch's pkgbase. Where it doesn't, three rules and a curated table
(aliases.json) fill in:
  - multilib `lib32-foo` is built from `foo`;
  - versioned source names, built from Arch's own version so only the
    matching release line is picked: python 3.14 -> python3.14, postgresql
    18 -> postgresql-18, php 8.5 -> php8.5 / php85, gcc 16 -> gcc-16;
  - `python-foo` -> Alpine `py3-foo` and PyPI `foo`.
The kernel packages map to OSV's Linux/Kernel through aliases.json.
Candidates are only used when some record actually carries that name.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .versions import tokens

FAMILIES = ("Debian", "Alpine", "PyPI", "Linux")


def family(ecosystem: str) -> str:
    """"Debian:13" -> "Debian"."""
    return ecosystem.split(":", 1)[0]


def load_aliases(path: Path) -> dict[str, dict[str, list[str]]]:
    if not path.exists():
        return {}
    raw = json.loads(path.read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def pypi_normalize(name: str) -> str:
    """PEP 503 name normalization."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _expand(template: str, version: str) -> str | None:
    nums = [t for t in tokens(version) if t.isdigit()]
    if ("{major}" in template and not nums) or ("{minor}" in template and len(nums) < 2):
        return None
    return template.format(major=nums[0] if nums else "", minor=nums[1] if len(nums) > 1 else "")


def candidates(pkgbase: str, upstream: str, aliases: dict[str, dict[str, list[str]]]) -> dict[str, list[str]]:
    """{family: [lowercase names]} to look up for this pkgbase."""
    base = pkgbase[len("lib32-"):] if pkgbase.startswith("lib32-") else pkgbase
    nums = [t for t in tokens(upstream) if t.isdigit()]
    auto = [base]
    if nums:
        maj = nums[0]
        auto += [f"{base}{maj}", f"{base}-{maj}"]
        if len(nums) > 1:
            mn = nums[1]
            auto += [f"{base}{maj}.{mn}", f"{base}-{maj}.{mn}", f"{base}{maj}{mn}"]
    out: dict[str, list[str]] = {"Debian": list(auto), "Alpine": list(auto), "PyPI": [], "Linux": []}
    if base.startswith("python-"):
        out["Alpine"].append("py3-" + base[len("python-"):])
        out["PyPI"].append(pypi_normalize(base[len("python-"):]))
    for fam, names in (aliases.get(base) or aliases.get(pkgbase) or {}).items():
        if fam not in out:
            continue
        if not names:  # explicit opt-out for a known collision
            out[fam] = []
            continue
        for t in names:
            n = _expand(t, upstream)
            if n:
                out[fam].append(n if fam != "PyPI" else pypi_normalize(n))
    return {fam: list(dict.fromkeys(n.lower() for n in names)) for fam, names in out.items()}
