#!/usr/bin/env python3
"""
Cross-check the tracker's output (data/vulns.json) against independent sources.

Precision — for every package/CVE pair the tracker reports, ask:
  * NIST NVD    (services.nvd.nist.gov, CVE API 2.0): do the record's CPE
                version ranges include Arch's version?
  * MITRE CVE   (CVEProject/cvelistV5, the official CVE List in JSON 5):
                do the CNA's / ADP's `affected` version ranges include it?
Recall — which Arch packages does Repology flag as vulnerable that the
tracker doesn't list, and vice versa?

Writes reports/compare.json and reports/compare.md.

Env:
  NVD_API_KEY   optional; raises NVD's rate limit from 5 to 50 req / 30 s
  NVD_MAX       max CVEs to look up in NVD (default 600)
  SKIP_NVD / SKIP_MITRE / SKIP_REPOLOGY   set to 1 to skip a source
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from update import upstream_version, vercmp  # noqa: E402

REPORTS = ROOT / "reports"
UA = "arch-unofficial-security-tracker/compare (+https://github.com/yetanotherf0rked/arch-unofficial-security-tracker)"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}"
MITRE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}xxx/{id}.json"
REPOLOGY_URL = "https://repology.org/api/v1/projects/{bound}?inrepo=arch&vulnerable=1"

NVD_KEY = os.environ.get("NVD_API_KEY", "")
NVD_DELAY = 0.7 if NVD_KEY else 6.5
NVD_MAX = int(os.environ.get("NVD_MAX", "600"))

# Vendors whose CPE / product entries describe a distro build, not upstream.
DISTRO_VENDORS = {
    "debian", "canonical", "redhat", "red hat", "fedoraproject", "opensuse", "suse",
    "novell", "oracle", "alpinelinux", "archlinux", "gentoo", "netapp", "apple",
    "microsoft", "siemens",
}


def get_json(url: str, headers: dict[str, str] | None = None, retries: int = 3) -> Any:
    last: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            last = e
            time.sleep(10 * (attempt + 1) if e.code in (403, 429, 503) else 2 ** attempt)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last = e
            time.sleep(2 ** attempt)
    raise RuntimeError(f"GET {url}: {last}")


def norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def names_match(pkg: str, candidate: str) -> bool:
    a, b = norm(pkg), norm(candidate)
    return bool(a and b) and (a == b or (len(a) >= 4 and (a in b or b in a)))


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

def _cpe_fields(criteria: str) -> list[str]:
    # cpe:2.3:part:vendor:product:version:update:...
    return criteria.split(":")


def _in_nvd_match(m: dict, version: str) -> bool | None:
    """True/False if `version` is (not) in this cpeMatch; None if undecidable."""
    f = _cpe_fields(m.get("criteria", ""))
    if len(f) < 7:
        return None
    ver, upd = f[5], f[6]
    bounds = [k for k in ("versionStartIncluding", "versionStartExcluding",
                          "versionEndIncluding", "versionEndExcluding") if k in m]
    if ver not in ("*", "-") and not bounds:
        exact = ver + (upd if upd not in ("*", "-") else "")
        return vercmp(version, upstream_version(exact)) == 0
    if not bounds:
        return None  # "all versions" — says nothing useful about Arch's version
    ok = True
    if "versionStartIncluding" in m:
        ok &= vercmp(version, m["versionStartIncluding"]) >= 0
    if "versionStartExcluding" in m:
        ok &= vercmp(version, m["versionStartExcluding"]) > 0
    if "versionEndIncluding" in m:
        ok &= vercmp(version, m["versionEndIncluding"]) <= 0
    if "versionEndExcluding" in m:
        ok &= vercmp(version, m["versionEndExcluding"]) < 0
    return ok


def nvd_verdict(rec: dict | None, pkg: str, version: str) -> dict[str, Any]:
    if rec is None:
        return {"verdict": "missing"}
    cve = rec.get("cve", {})
    status = cve.get("vulnStatus", "")
    if status == "Rejected":
        return {"verdict": "rejected"}
    matches = [
        m for cfg in cve.get("configurations", []) or []
        for node in cfg.get("nodes", []) or []
        for m in node.get("cpeMatch", []) or []
        if m.get("vulnerable")
    ]
    if not matches:
        return {"verdict": "no_data", "status": status}
    named = [m for m in matches if names_match(pkg, _cpe_fields(m["criteria"])[4])]
    pool = named or [m for m in matches if _cpe_fields(m["criteria"])[3] not in DISTRO_VENDORS]
    results = [r for r in (_in_nvd_match(m, version) for m in pool) if r is not None]
    products = sorted({":".join(_cpe_fields(m["criteria"])[3:5]) for m in pool})[:3]
    if not results:
        return {"verdict": "no_data", "status": status, "products": products}
    return {
        "verdict": "affected" if any(results) else "not_affected",
        "matched_by": "name" if named else "any_product",
        "products": products,
        "status": status,
    }


def fetch_nvd(ids: list[str]) -> dict[str, dict | None]:
    out: dict[str, dict | None] = {}
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    for i, cid in enumerate(ids):
        try:
            data = get_json(NVD_URL.format(id=cid), headers)
            vulns = (data or {}).get("vulnerabilities") or []
            out[cid] = vulns[0] if vulns else None
        except Exception as e:
            print(f"  nvd {cid}: {e}", file=sys.stderr)
            out[cid] = None
        if (i + 1) % 50 == 0:
            print(f"  nvd {i + 1}/{len(ids)}", flush=True)
        time.sleep(NVD_DELAY)
    return out


# ---------------------------------------------------------------------------
# MITRE CVE List (JSON 5)
# ---------------------------------------------------------------------------

def mitre_url(cid: str) -> str:
    _, year, num = cid.split("-")
    return MITRE_URL.format(year=year, bucket=int(num) // 1000, id=cid)


def _in_mitre_entry(entry: dict, version: str) -> bool | None:
    verdict: bool | None = None
    for v in entry.get("versions", []) or []:
        if v.get("versionType") in ("git", "rpm", "deb"):
            continue
        lo = v.get("version", "")
        hi_lt, hi_le = v.get("lessThan"), v.get("lessThanOrEqual")
        if hi_lt is None and hi_le is None:
            inside = lo not in ("", "*") and vercmp(version, upstream_version(lo)) == 0
        else:
            inside = lo in ("0", "", "*") or vercmp(version, upstream_version(lo)) >= 0
            if hi_lt not in (None, "*"):
                inside = inside and vercmp(version, upstream_version(hi_lt)) < 0
            if hi_le not in (None, "*"):
                inside = inside and vercmp(version, upstream_version(hi_le)) <= 0
        if inside:
            return v.get("status") == "affected"
    # Outside every listed range: fall back to defaultStatus. CNAs often omit it
    # while listing "affected < X"; read that as fixed from X on.
    default = entry.get("defaultStatus")
    has_affected_range = any(
        v.get("status") == "affected" and (v.get("lessThan") or v.get("lessThanOrEqual"))
        and v.get("versionType") not in ("git", "rpm", "deb")
        for v in entry.get("versions", []) or []
    )
    if default == "affected":
        verdict = True
    elif default == "unaffected" and entry.get("versions"):
        verdict = False
    elif default in (None, "unknown") and has_affected_range:
        verdict = False
    return verdict


def mitre_verdict(rec: dict | None, pkg: str, version: str) -> dict[str, Any]:
    if rec is None:
        return {"verdict": "missing"}
    if rec.get("cveMetadata", {}).get("state") == "REJECTED":
        return {"verdict": "rejected"}
    containers = rec.get("containers", {})
    entries = list(containers.get("cna", {}).get("affected", []) or [])
    for adp in containers.get("adp", []) or []:
        entries.extend(adp.get("affected", []) or [])
    upstream = [e for e in entries if norm(e.get("vendor", "")) not in {norm(v) for v in DISTRO_VENDORS}]
    named = [
        e for e in upstream
        if names_match(pkg, e.get("packageName", "")) or names_match(pkg, e.get("product", ""))
    ]
    pool = named or upstream
    results = [r for r in (_in_mitre_entry(e, version) for e in pool) if r is not None]
    products = sorted({f"{e.get('vendor', '?')}:{e.get('product') or e.get('packageName', '?')}" for e in pool})[:3]
    if not results:
        return {"verdict": "no_data", "products": products}
    return {
        "verdict": "affected" if any(results) else "not_affected",
        "matched_by": "name" if named else "any_product",
        "products": products,
    }


def fetch_mitre(ids: list[str]) -> dict[str, dict | None]:
    def one(cid: str) -> tuple[str, dict | None]:
        try:
            return cid, get_json(mitre_url(cid))
        except Exception as e:
            print(f"  mitre {cid}: {e}", file=sys.stderr)
            return cid, None
    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(pool.map(one, ids))


# ---------------------------------------------------------------------------
# Repology
# ---------------------------------------------------------------------------

def fetch_repology() -> tuple[dict[str, dict[str, Any]], str]:
    """
    {arch srcname: {project, version}} for Arch packages Repology flags as
    vulnerable, plus a note on how the flag was interpreted.
    """
    flagged: dict[str, dict[str, Any]] = {}
    bound, seen = "", set()
    has_pkg_flag = False
    while True:
        page = get_json(REPOLOGY_URL.format(bound=urllib.parse.quote(bound + "/") if bound else ""))
        time.sleep(1.1)  # Repology policy: at most one request per second
        new = [p for p in (page or {}) if p not in seen]
        if not new:
            break
        for project in new:
            seen.add(project)
            for pkg in page[project]:
                if pkg.get("repo") != "arch":
                    continue
                if "vulnerable" in pkg:
                    has_pkg_flag = True
                    if not pkg["vulnerable"]:
                        continue
                name = pkg.get("srcname") or pkg.get("binname") or project
                flagged[name] = {"project": project, "version": pkg.get("version")}
        bound = max(new)
    note = (
        "per-package `vulnerable` flag on Arch entries"
        if has_pkg_flag
        else "project-level filter (inrepo=arch&vulnerable=1): the vulnerable package may be "
             "in another distro, so Repology-only entries overstate Arch exposure"
    )
    return flagged, note


# ---------------------------------------------------------------------------

def main() -> int:
    data = json.loads((ROOT / "data" / "vulns.json").read_text())
    if not data.get("affected"):
        print("data/vulns.json has no entries — run update.py first", file=sys.stderr)
        return 1

    pairs: list[dict[str, Any]] = []
    for a in data["affected"]:
        for kind in ("vulns", "uncertain", "unfixed"):
            for v in a.get(kind, []) or []:
                if v.get("cve"):
                    pairs.append({
                        "package": a["name"], "repo": a["repo"], "version": a["version"],
                        "upstream_version": a["upstream_version"], "cve": v["cve"],
                        "kind": {"vulns": "fixable"}.get(kind, kind),
                        "fixed_versions": v.get("fixed_versions", []),
                    })
    cve_ids = sorted({p["cve"] for p in pairs})
    print(f"{len(pairs)} package/CVE pairs, {len(cve_ids)} unique CVEs", flush=True)

    mitre: dict[str, dict | None] = {}
    if os.environ.get("SKIP_MITRE") != "1":
        print("Fetching MITRE CVE List records...", flush=True)
        mitre = fetch_mitre(cve_ids)

    nvd: dict[str, dict | None] = {}
    nvd_ids: list[str] = []
    if os.environ.get("SKIP_NVD") != "1":
        # Fixable pairs first: they are the tracker's headline claims.
        ordered = sorted(cve_ids, key=lambda c: (all(p["kind"] == "unfixed" for p in pairs if p["cve"] == c), c))
        nvd_ids = ordered[:NVD_MAX]
        print(f"Fetching NVD records for {len(nvd_ids)} CVEs (delay {NVD_DELAY}s)...", flush=True)
        nvd = fetch_nvd(nvd_ids)

    for p in pairs:
        if mitre:
            p["mitre"] = mitre_verdict(mitre.get(p["cve"]), p["package"], p["upstream_version"])
        if p["cve"] in nvd:
            p["nvd"] = nvd_verdict(nvd[p["cve"]], p["package"], p["upstream_version"])

    repology: dict[str, dict[str, Any]] = {}
    repology_note = "skipped"
    if os.environ.get("SKIP_REPOLOGY") != "1":
        print("Fetching Repology vulnerable projects for Arch...", flush=True)
        try:
            repology, repology_note = fetch_repology()
        except Exception as e:
            repology_note = f"failed: {e}"
            print(f"  repology: {e}", file=sys.stderr)

    ours = {a["name"] for a in data["affected"]}
    ours_fixable = {a["name"] for a in data["affected"] if a.get("vulns")}
    rep_names = set(repology)

    def tally(source: str, kind: str) -> dict[str, int]:
        t: dict[str, int] = {}
        for p in pairs:
            if p["kind"] == kind and source in p:
                k = p[source]["verdict"]
                t[k] = t.get(k, 0) + 1
        return dict(sorted(t.items()))

    report = {
        "generated_at": int(time.time()),
        "tracker_generated_at": data.get("generated_at"),
        "pairs": len(pairs),
        "unique_cves": len(cve_ids),
        "nvd_checked": len(nvd_ids),
        "precision": {
            src: {kind: tally(src, kind) for kind in ("fixable", "uncertain", "unfixed")}
            for src in ("nvd", "mitre")
        },
        "repology": {
            "note": repology_note,
            "flagged": len(rep_names),
            "both": sorted(ours & rep_names),
            "repology_only": sorted(rep_names - ours),
            "tracker_only": sorted(ours - rep_names),
        },
        "disagreements": [
            p for p in pairs
            if p["kind"] == "fixable"
            and (p.get("nvd", {}).get("verdict") == "not_affected"
                 or p.get("mitre", {}).get("verdict") == "not_affected")
        ],
        "detail": pairs,
    }
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "compare.json").write_text(json.dumps(report, indent=1))
    (REPORTS / "compare.md").write_text(render_md(report, ours_fixable, repology))
    print((REPORTS / "compare.md").read_text())
    return 0


def render_md(r: dict[str, Any], ours_fixable: set[str], repology: dict[str, dict]) -> str:
    def row(src: str, kind: str) -> str:
        t = r["precision"][src][kind]
        n = sum(t.values())
        if not n:
            return f"| {src.upper()} | {kind} | – | – | – | – |"
        aff, notaff = t.get("affected", 0), t.get("not_affected", 0)
        other = n - aff - notaff
        decided = aff + notaff
        agree = f"{100 * aff / decided:.0f}%" if decided else "–"
        return f"| {src.upper()} | {kind} | {aff} | {notaff} | {other} | {agree} |"

    rep = r["repology"]
    lines = [
        "# Source comparison",
        "",
        f"Tracker data from {time.strftime('%Y-%m-%d %H:%MZ', time.gmtime(r['tracker_generated_at'] or 0))}: "
        f"{r['pairs']} package/CVE pairs, {r['unique_cves']} unique CVEs "
        f"(NVD checked for {r['nvd_checked']}).",
        "",
        "## Precision: does the official record agree Arch's version is affected?",
        "",
        "| Source | Tracker says | Agrees (affected) | Disagrees (not affected) | No version data / missing | Agreement where decidable |",
        "|---|---|---|---|---|---|",
        row("nvd", "fixable"), row("nvd", "uncertain"), row("nvd", "unfixed"),
        row("mitre", "fixable"), row("mitre", "uncertain"), row("mitre", "unfixed"),
        "",
        "\"No version data\" means the record has no usable ranges for this product "
        "(NVD awaiting analysis, CNA gave only git commits, etc.).",
        "",
        f"## Recall: Repology ({rep['note']})",
        "",
        f"- Flagged by Repology: **{rep['flagged']}** Arch packages",
        f"- Flagged by both: **{len(rep['both'])}**",
        f"- Repology only: **{len(rep['repology_only'])}**",
        f"- Tracker only: **{len(rep['tracker_only'])}** "
        f"({len(set(rep['tracker_only']) & ours_fixable)} with a fixable CVE)",
        "",
    ]
    if rep["repology_only"]:
        lines += ["<details><summary>Repology only</summary>", ""]
        lines += [f"- `{n}` {repology[n].get('version', '')} ({repology[n]['project']})" for n in rep["repology_only"][:300]]
        lines += ["", "</details>", ""]
    if rep["tracker_only"]:
        lines += ["<details><summary>Tracker only</summary>", ""]
        lines += [f"- `{n}`" for n in rep["tracker_only"][:300]]
        lines += ["", "</details>", ""]
    lines += [
        "## Disagreements on fixable CVEs",
        "",
        "| Package | Arch | CVE | Tracker fix | NVD | MITRE |",
        "|---|---|---|---|---|---|",
    ]
    for p in r["disagreements"][:200]:
        def cell(src: str) -> str:
            v = p.get(src)
            if not v:
                return "–"
            extra = f" ({', '.join(v.get('products', [])[:2])})" if v.get("products") else ""
            return v["verdict"] + extra
        lines.append(
            f"| {p['package']} | {p['upstream_version']} | {p['cve']} | "
            f"{', '.join(p['fixed_versions'][:2])} | {cell('nvd')} | {cell('mitre')} |"
        )
    if len(r["disagreements"]) > 200:
        lines.append(f"\n…and {len(r['disagreements']) - 200} more in compare.json")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
