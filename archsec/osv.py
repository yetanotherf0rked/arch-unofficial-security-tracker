"""
OSV.dev bulk exports: one zip per ecosystem with every record as JSON.
https://google.github.io/osv.dev/data/#data-dumps
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from pathlib import Path
from typing import Any, Callable

from .names import family, pypi_normalize
from .net import http_get

EXPORT_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
ADVISORY_ID = re.compile(r"^(?:DSA|DLA|DTSA)-")


def _key_name(fam: str, name: str) -> str:
    return pypi_normalize(name) if fam == "PyPI" else name.lower()


def load_exports(
    ecosystems: tuple[str, ...],
    wanted: dict[str, set[str]],
    fetch: Callable[[str], bytes] | None = None,
    local_dir: Path | None = None,
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """
    {(family, name): [records]} for the names in `wanted[family]`. Withdrawn
    records are skipped. `local_dir` reads `<ecosystem>.zip` files instead of
    downloading (offline runs, tests).
    """
    index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for eco in ecosystems:
        fam = family(eco)
        names = wanted.get(fam, set())
        if not names:
            continue
        if local_dir is not None:
            blob = (local_dir / f"{eco}.zip").read_bytes()
        else:
            url = EXPORT_URL.format(ecosystem=eco)
            print(f"  fetching {url}", flush=True)
            blob = (fetch or http_get)(url)
        kept = total = 0
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for info in zf.infolist():
                if not info.filename.endswith(".json"):
                    continue
                total += 1
                try:
                    rec = json.loads(zf.read(info))
                except json.JSONDecodeError:
                    continue
                if rec.get("withdrawn"):
                    continue
                hit = {
                    key for aff in rec.get("affected", []) or []
                    if (key := _key_name(fam, (aff.get("package") or {}).get("name", ""))) in names
                }
                for key in hit:
                    index.setdefault((fam, key), []).append(rec)
                kept += bool(hit)
        print(f"    {eco}: {total} records, {kept} for Arch package names", flush=True)
    return index


def cve_of(record: dict[str, Any]) -> str:
    """The CVE a record is about, if any."""
    for ident in [record.get("id", "")] + (record.get("aliases") or []) + (record.get("upstream") or []):
        m = _CVE_RE.fullmatch(ident) or (_CVE_RE.search(ident) if ident.startswith(("DEBIAN-", "ALPINE-")) else None)
        if m:
            return m.group(0)
    return ""


def group_key(record: dict[str, Any]) -> str:
    """
    Records about the same issue share a key: the CVE, else the smallest of
    id/aliases (GHSA/PYSEC pairs). Debian DSA/DLA advisories cover several
    CVEs and keep their own id.
    """
    if ADVISORY_ID.match(record.get("id", "")):
        return record["id"]
    return cve_of(record) or min([record.get("id", "")] + (record.get("aliases") or []))
