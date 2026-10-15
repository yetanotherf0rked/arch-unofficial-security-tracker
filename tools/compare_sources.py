#!/usr/bin/env python3
"""
Cross-check the tracker's feed (data/advisories.json) against independent sources.

Precision — for every package/CVE pair the tracker reports, ask:
  * NIST NVD    (CVE API 2.0 records, read from the fkie-cad/nvd-json-data-feeds
                mirror on GitHub): do the record's CPE version ranges include
                Arch's version?
  * MITRE CVE   (CVEProject/cvelistV5, the official CVE List in JSON 5):
                do the CNA's / ADP's `affected` version ranges include it?
Misses — for a sample of recent issues the tracker considers fixed in the
repos, do NVD / MITRE say Arch's version is still affected?
Recall — which Arch packages does Repology flag as vulnerable that the
tracker doesn't list, and vice versa?

Writes reports/compare.json and reports/compare.md.

Env:
  NVD_API_KEY   optional; lets CVEs not yet in the mirror fall back to NVD's
                own API (without a key that API allows 5 requests / 30 s)
  SKIP_NVD / SKIP_MITRE / SKIP_REPOLOGY   set to 1 to skip a source
  FIXED_SAMPLE  how many recent "fixed" pairs to check for misses (default 1500)
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
from archsec.versions import split_arch, upstream_version, vercmp  # noqa: E402

REPORTS = ROOT / "reports"
UA = "arch-unofficial-security-tracker/compare (+https://github.com/yetanotherf0rked/arch-unofficial-security-tracker)"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}"
# Community mirror of the NVD API, synced every 2 hours: one static file per CVE,
# so no API rate limit and none of the API's frequent 503s.
NVD_MIRROR_URL = "https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main/{year}/{bucket}xx/{id}.json"
MITRE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}xxx/{id}.json"
REPOLOGY_URL = "https://repology.org/api/v1/projects/{bound}?inrepo=arch&vulnerable=1"

NVD_KEY = os.environ.get("NVD_API_KEY", "")
FIXED_SAMPLE = int(os.environ.get("FIXED_SAMPLE", "1500"))
KINDS = ("vulnerable", "unfixed", "uncertain", "fixed")

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
        # A list of exact versions proves those versions are affected; it says
        # nothing about versions it doesn't list.
        exact = ver + (upd if upd not in ("*", "-") else "")
        return True if vercmp(version, upstream_version(exact)) == 0 else None
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


def nvd_mirror_url(cid: str) -> str:
    year = cid.split("-")[1]
    return NVD_MIRROR_URL.format(year=f"CVE-{year}", bucket=cid[:-2], id=cid)


def fetch_nvd(ids: list[str]) -> dict[str, dict | None]:
    """NVD records from the GitHub mirror; API fallback (keyed only) for misses."""
    def one(cid: str) -> tuple[str, dict | None]:
        try:
            rec = get_json(nvd_mirror_url(cid))
            return cid, {"cve": rec} if rec else None
        except Exception as e:
            print(f"  nvd mirror {cid}: {e}", file=sys.stderr)
            return cid, None

    with ThreadPoolExecutor(max_workers=8) as pool:
        out = dict(pool.map(one, ids))
    misses = [c for c, r in out.items() if r is None]
    print(f"  nvd mirror: {len(ids) - len(misses)} found, {len(misses)} missing", flush=True)
    if misses and NVD_KEY:
        for cid in misses:
            try:
                data = get_json(NVD_URL.format(id=cid), {"apiKey": NVD_KEY})
                vulns = (data or {}).get("vulnerabilities") or []
                out[cid] = vulns[0] if vulns else None
            except Exception as e:
                print(f"  nvd api {cid}: {e}", file=sys.stderr)
            time.sleep(0.7)  # keyed limit: 50 requests / 30 s
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
            hi = hi_lt if hi_lt not in (None, "*") else hi_le
            # Some CNAs (e.g. Chrome) write version == lessThan to mean "below X":
            # a lower bound that isn't below the upper one carries no information.
            no_lower = lo in ("0", "", "*") or (
                hi not in (None, "*") and vercmp(upstream_version(lo), upstream_version(hi)) >= 0
            )
            inside = no_lower or vercmp(version, upstream_version(lo)) >= 0
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

def collect_pairs(feed: dict[str, Any]) -> list[dict[str, Any]]:
    """Package/CVE pairs to check: every open issue, plus the most recent fixed ones."""
    pairs: list[dict[str, Any]] = []
    fixed: list[dict[str, Any]] = []
    for name, b in feed["pkgbases"].items():
        up = upstream_version(split_arch(b["version"])[1])
        common = {"package": name, "repo": b["repo"], "version": b["version"], "upstream_version": up}
        for i in b.get("issues", []):
            if i["id"].startswith("CVE-"):
                pairs.append({**common, "cve": i["id"], "kind": i["status"], "reason": i.get("reason", ""),
                              "fixed_versions": i.get("fix", [])})
        for g in b.get("fixed", []):
            for cid in g["ids"]:
                if cid.startswith("CVE-"):
                    fixed.append({**common, "cve": cid, "kind": "fixed", "reason": "",
                                  "fixed_versions": [g["fixed"]], "published": g.get("published", "")})
    # Most recent first, at most 40 per package so the kernel doesn't fill the sample.
    fixed.sort(key=lambda p: p["published"], reverse=True)
    per_pkg: dict[str, int] = {}
    sample = []
    for p in fixed:
        if per_pkg.get(p["package"], 0) < 40 and len(sample) < FIXED_SAMPLE:
            per_pkg[p["package"]] = per_pkg.get(p["package"], 0) + 1
            sample.append(p)
    return pairs + sample


def main() -> int:
    feed_path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "_site" / "data" / "advisories.json"
    if not feed_path.exists():
        print(f"{feed_path} not found — run `python update.py` first", file=sys.stderr)
        return 1
    data = json.loads(feed_path.read_text())

    pairs = collect_pairs(data)
    cve_ids = sorted({p["cve"] for p in pairs})
    print(f"{len(pairs)} package/CVE pairs, {len(cve_ids)} unique CVEs", flush=True)

    mitre: dict[str, dict | None] = {}
    if os.environ.get("SKIP_MITRE") != "1":
        print("Fetching MITRE CVE List records...", flush=True)
        mitre = fetch_mitre(cve_ids)

    nvd: dict[str, dict | None] = {}
    nvd_ids: list[str] = []
    if os.environ.get("SKIP_NVD") != "1":
        nvd_ids = cve_ids
        print(f"Fetching NVD records for {len(nvd_ids)} CVEs...", flush=True)
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

    open_status = ("vulnerable", "unfixed")
    ours = {n for n, b in data["pkgbases"].items() if any(i["status"] in open_status and not i.get("minor") for i in b["issues"])}
    ours_fixable = {n for n, b in data["pkgbases"].items() if any(i["status"] == "vulnerable" for i in b["issues"])}
    rep_names = set(repology)

    def tally(source: str, kind: str) -> dict[str, int]:
        t: dict[str, int] = {}
        for p in pairs:
            if p["kind"] == kind and source in p:
                k = p[source]["verdict"]
                t[k] = t.get(k, 0) + 1
        return dict(sorted(t.items()))

    def says(p: dict, verdict: str) -> bool:
        return p.get("nvd", {}).get("verdict") == verdict or p.get("mitre", {}).get("verdict") == verdict

    report = {
        "generated_at": int(time.time()),
        "tracker_generated_at": data.get("generated_at"),
        "pairs": len(pairs),
        "unique_cves": len(cve_ids),
        "nvd_checked": len(nvd_ids),
        "precision": {src: {kind: tally(src, kind) for kind in KINDS} for src in ("nvd", "mitre")},
        "repology": {
            "note": repology_note,
            "flagged": len(rep_names),
            "both": sorted(ours & rep_names),
            "repology_only": sorted(rep_names - ours),
            "tracker_only": sorted(ours - rep_names),
        },
        "disagreements": [p for p in pairs if p["kind"] == "vulnerable" and says(p, "not_affected")],
        "possible_misses": [p for p in pairs if p["kind"] == "fixed" and says(p, "affected")],
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
        # For "fixed" pairs the tracker claims Arch is *not* affected.
        agreeing = notaff if kind == "fixed" else aff
        agree = f"{100 * agreeing / decided:.0f}%" if decided else "–"
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
        "| Source | Tracker says | Source: affected | Source: not affected | No version data / missing | Agreement where decidable |",
        "|---|---|---|---|---|---|",
        *(row(src, kind) for src in ("nvd", "mitre") for kind in KINDS),
        "",
        "\"fixed\" rows are a sample of recent issues the tracker considers fixed in the repos; "
        "agreement there means the source also says Arch's version is not affected.",
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
        f"({len(set(rep['tracker_only']) & ours_fixable)} vulnerable with an upstream fix)",
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
    def cell(p: dict, src: str) -> str:
        v = p.get(src)
        if not v:
            return "–"
        extra = f" ({', '.join(v.get('products', [])[:2])})" if v.get("products") else ""
        return v["verdict"] + extra

    lines += [
        "## Possible misses: tracker says fixed, NVD or MITRE says affected",
        "",
        "| Package | Arch | CVE | Tracker threshold | NVD | MITRE |",
        "|---|---|---|---|---|---|",
    ]
    for p in r["possible_misses"][:200]:
        lines.append(f"| {p['package']} | {p['upstream_version']} | {p['cve']} | "
                     f"{', '.join(p['fixed_versions'][:2])} | {cell(p, 'nvd')} | {cell(p, 'mitre')} |")
    lines += [
        "",
        "## Disagreements on vulnerable CVEs",
        "",
        "| Package | Arch | CVE | Tracker fix | NVD | MITRE |",
        "|---|---|---|---|---|---|",
    ]
    for p in r["disagreements"][:200]:
        lines.append(
            f"| {p['package']} | {p['upstream_version']} | {p['cve']} | "
            f"{', '.join(p['fixed_versions'][:2])} | {cell(p, 'nvd')} | {cell(p, 'mitre')} |"
        )
    if len(r["disagreements"]) > 200:
        lines.append(f"\n…and {len(r['disagreements']) - 200} more in compare.json")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
