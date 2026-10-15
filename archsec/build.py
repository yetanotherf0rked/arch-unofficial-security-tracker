"""
Build the feed.

  Arch repo DBs ──► pkgbases (name, version, split packages)
                         │  names.candidates (+ aliases.json)
  OSV exports ───► records per (ecosystem family, name)
                         │  group by CVE, match.evaluate
                         ▼
  data/advisories.json   every repo package -> pkgbase, and per pkgbase the
                         issues with Arch-format thresholds (`fixed`)
  all.json               the same in the format of security.archlinux.org's
                         all.json, for `arch-audit --source`

Thresholds are written as Arch versions so clients compare them with the
installed version using pacman's own ordering; all fuzzy matching happens
here, once.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import archrepo, names, osv, severity
from .check import vercmp as alpm_vercmp
from .match import evaluate, relevant_entries
from .versions import arch_form, split_arch, upstream_version

ROOT = Path(__file__).resolve().parent.parent
MIRROR = os.environ.get("ARCH_MIRROR", "https://geo.mirror.pkgbuild.com")
# Linux is the kernel CNA's data (per-branch fixed versions). Ubuntu is left
# out by default: its export is ~780 MB and mostly mirrors Debian's data (it
# contributed no finding Debian didn't already have).
ECOSYSTEMS = tuple(e for e in os.environ.get("OSV_ECOSYSTEMS", "Debian,Alpine,PyPI,Linux").split(",") if e)
# When Arch has a fix but the upstream version that brought it can't be
# written as an Arch version, the current repo version is the threshold.
# That over-reports for machines between the real fix and the current
# version, so it is only done for issues published this recently.
RECENT_DAYS = 120
# all.json is fetched on every arch-audit run; it lists fixed issues from
# this many days back (advisories.json keeps them all).
ARCH_AUDIT_FIXED_DAYS = 730

FEED_SCHEMA = 1


def _ts(iso: str) -> int:
    """Unix time of an OSV timestamp ("2026-10-13T12:00:18.784933686Z"); 0 if unparseable."""
    m = re.match(r"(\d{4}-\d{2}-\d{2})(?:T(\d{2}:\d{2}(?::\d{2})?))?", iso or "")
    if not m:
        return 0
    when = datetime.fromisoformat(f"{m.group(1)}T{m.group(2) or '00:00'}").replace(tzinfo=timezone.utc)
    return int(when.timestamp())


def _clip(text: str, n: int) -> str:
    """Shorten to at most n characters at a word boundary."""
    text = " ".join(text.split())
    if len(text) <= n:
        return text
    return text[: n - 1].rsplit(" ", 1)[0].rstrip(",.;:") + "…"


def group_pkgbases(packages: list[dict]) -> dict[str, dict[str, Any]]:
    """One entry per pkgbase: split packages share a source and an issue list."""
    bases: dict[str, dict[str, Any]] = {}
    for p in packages:
        b = bases.setdefault(p["base"], {
            "repo": p["repo"], "version": p["version"], "arch": p.get("arch", archrepo.ARCH),
            "url": p.get("url", ""), "builddate": 0, "packages": [],
        })
        b["packages"].append(p["name"])
        b["builddate"] = max(b["builddate"], p.get("builddate", 0))
        if p["name"] == p["base"]:  # the package named like its base links best
            b["arch"], b["url"] = p.get("arch", archrepo.ARCH), p.get("url", "") or b["url"]
    return bases


def _record_meta(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Summary, severity, dates and references for a group of records about one issue."""
    score = None
    vector = ""
    for r in records:
        for s in r.get("severity", []) or []:
            sc = severity.cvss3_score(s.get("score", ""))
            if sc is not None and (score is None or sc > score):
                score, vector = sc, s["score"]
            elif not vector and s.get("type", "").startswith("CVSS"):
                vector = s.get("score", "")
    text = next((r.get("summary") or r.get("details") for r in records if r.get("summary") or r.get("details")), "")
    published = min((_ts(r.get("published", "")) for r in records if r.get("published")), default=0)
    refs: list[str] = []
    for r in records:
        refs.extend(x.get("url") for x in (r.get("references") or [])[:5] if x.get("url"))
    return {
        "score": score, "vector": vector, "summary": _clip(text.strip(), 300),
        "published": published, "refs": list(dict.fromkeys(refs))[:5],
    }


def assess_pkgbase(
    base: str, info: dict[str, Any], index: dict[tuple[str, str], list[dict]],
    aliases: dict[str, Any], now: int, stats: dict[str, int],
) -> tuple[list[str], list[dict[str, Any]], list[dict[str, Any]]]:
    """
    (sources, issues, fixed) for one pkgbase: the names that had records,
    the issues affecting the repo version, and the issues the repo version
    has fixed, grouped by the Arch version that fixes them.
    """
    full = info["version"]
    _, pkgver, _ = split_arch(full)
    up = upstream_version(pkgver)
    found: set[tuple[str, str]] = set()
    recs: dict[str, dict] = {}
    for fam, cands in names.candidates(base, up, aliases).items():
        for n in cands:
            for r in index.get((fam, n), []):
                found.add((fam, n))
                recs.setdefault(r["id"], r)
    if not recs:
        return [], [], []

    # Group by issue; Debian DSA/DLA advisories that only repeat per-CVE
    # records are skipped.
    groups: dict[str, list[dict]] = {}
    for r in recs.values():
        groups.setdefault(osv.group_key(r), []).append(r)
    own = set(groups)
    issues = []
    fixed_groups: dict[str, dict[str, Any]] = {}
    for key, rs in groups.items():
        rs = [r for r in rs if not (
            osv.ADVISORY_ID.match(r.get("id", ""))
            and (ups := {u for u in r.get("upstream", []) or [] if u.startswith("CVE-")})
            and ups <= own - {key}
        )]
        if not rs:
            stats["duplicate_advisory"] += 1
            continue
        meta = _record_meta(rs)
        v = evaluate(relevant_entries(rs, found), up, info["builddate"], meta["published"])
        stats[v.status] = stats.get(v.status, 0) + 1
        if v.status in ("not_affected", "mismatch", "unknown"):
            continue
        sev = severity.rating(meta["score"])
        if sev == "Unknown":
            sev = severity.from_urgency(v.urgency)
        issue: dict[str, Any] = {"id": key, "status": v.status, "severity": sev}

        if v.status == "fixed":
            fixed = None
            if v.fixed_by:
                cand = arch_form(v.fixed_by, full)
                if alpm_vercmp(full, cand) >= 0:
                    fixed = cand
            if fixed is None and now - meta["published"] <= RECENT_DAYS * 86400:
                fixed = full
            if fixed is None or v.urgency == "unimportant":
                stats["fixed_dropped"] += 1
                continue
            g = fixed_groups.setdefault(fixed, {"fixed": fixed, "severity": "Unknown", "published": 0, "ids": []})
            g["ids"].append(key)
            g["published"] = max(g["published"], meta["published"])
            if severity.RATINGS.index(sev) > severity.RATINGS.index(g["severity"]):
                g["severity"] = sev
            continue

        issue["reason"] = v.reason
        if v.next_fix:
            cand = arch_form(v.next_fix, full)
            issue["fixed"] = cand if alpm_vercmp(full, cand) < 0 else None
            issue["fix"] = [v.next_fix]
        if v.patched_in and v.reason in ("patch-only", "distro-patch", "distro-patch-rebuilt"):
            issue["patched_in"] = v.patched_in[:3]
        if v.urgency:
            issue["urgency"] = v.urgency
        if v.urgency == "unimportant":
            issue["minor"] = True
        issue.update({
            "score": meta["score"], "vector": meta["vector"],
            "published": datetime.fromtimestamp(meta["published"], timezone.utc).strftime("%Y-%m-%dT%H:%MZ") if meta["published"] else "",
            "summary": meta["summary"], "refs": meta["refs"],
            "sources": sorted(r["id"] for r in rs),
        })
        issues.append(issue)
    order = {"vulnerable": 0, "unfixed": 1, "uncertain": 2}
    issues.sort(key=lambda i: (order[i["status"]], -_ts(i.get("published", "") or "1970-01-01"), i["id"]))
    fixed = sorted(fixed_groups.values(), key=lambda g: -g["published"])
    for g in fixed:
        g["ids"].sort(reverse=True)
        g["published"] = time.strftime("%Y-%m-%d", time.gmtime(g["published"])) if g["published"] else ""
    return sorted(f"{fam}:{n}" for fam, n in found), issues, fixed


def arch_audit_feed(bases: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Issues grouped the way security.archlinux.org's all.json groups them
    (one AVG per pkgbase, status and fixed version). Read by arch-audit:
    a package is listed when installed and below `fixed` (or `fixed` is
    null). Issues Debian rates unimportant are left out.
    """
    status_map = {"vulnerable": "Vulnerable", "unfixed": "Vulnerable", "uncertain": "Unknown"}
    cutoff = time.strftime("%Y-%m-%d", time.gmtime(time.time() - ARCH_AUDIT_FIXED_DAYS * 86400))
    out = []

    def avg(base: str, info: dict, st: str, fixed: str | None, ids: list[str], sev: str) -> dict[str, Any]:
        digest = hashlib.sha1(f"{base}|{st}|{fixed}".encode()).hexdigest()[:8].upper()
        return {
            "name": f"UAVG-{digest}",
            "packages": sorted(info["packages"]),
            "status": st,
            "severity": sev,
            "type": "possible security issues" if st == "Unknown" else "security issues",
            "affected": info["version"] if st != "Fixed" else None,
            "fixed": fixed,
            "ticket": None,
            "issues": ids,
            "advisories": [],
        }

    for base, info in sorted(bases.items()):
        groups: dict[str, list[dict]] = {}
        for i in info.get("issues", []):
            if not i.get("minor"):
                groups.setdefault(status_map[i["status"]], []).append(i)
        for st, issues in groups.items():
            sev = max(severity.RATINGS.index(i["severity"]) for i in issues)
            out.append(avg(base, info, st, None, [i["id"] for i in issues], severity.RATINGS[sev]))
        for g in info.get("fixed", []):
            if g["published"] >= cutoff:
                out.append(avg(base, info, "Fixed", g["fixed"], g["ids"], g["severity"]))
    return out


def build(packages: list[dict], index: dict[tuple[str, str], list[dict]], aliases: dict[str, Any],
          now: int | None = None) -> dict[str, Any]:
    now = now or int(time.time())
    bases = group_pkgbases(packages)
    stats: dict[str, int] = {"duplicate_advisory": 0, "fixed_dropped": 0}
    out: dict[str, Any] = {}
    for base, info in bases.items():
        sources, issues, fixed = assess_pkgbase(base, info, index, aliases, now, stats)
        if sources:
            out[base] = {**info, "sources": sources, "issues": issues, "fixed": fixed}

    def count(status: str, minor: bool | None = None) -> int:
        return sum(1 for b in out.values() for i in b["issues"]
                   if i["status"] == status and (minor is None or bool(i.get("minor")) == minor))

    return {
        "schema": FEED_SCHEMA,
        "generated_at": now,
        "sources": {
            "packages": f"{MIRROR}/<repo>/os/{archrepo.ARCH}/<repo>.db.tar.gz (repos: {', '.join(archrepo.REPOS)})",
            "vulnerabilities": "OSV.dev bulk exports: " + ", ".join(ECOSYSTEMS),
        },
        "limitations": (
            "Arch is not an OSV ecosystem: issues come from " + " / ".join(ECOSYSTEMS)
            + " records matched to Arch pkgbases by name (plus aliases), then checked against "
            "each record's version ranges. A fix that another distro made by patching (rather "
            "than by a new upstream release) does not count as an upstream fix. Packages "
            "without records under a matching name are not covered; Arch patches applied "
            "without a version change are not visible."
        ),
        "stats": {
            **stats,
            "pkgbases": len(bases), "covered_pkgbases": len(out),
            "vulnerable": count("vulnerable"), "unfixed": count("unfixed", False),
            "unfixed_minor": count("unfixed", True), "uncertain": count("uncertain"),
            "fixed_issues": sum(len(g["ids"]) for b in out.values() for g in b["fixed"]),
        },
        "packages": {p["name"]: p["base"] for p in packages},
        "pkgbases": out,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the tracker feed.")
    ap.add_argument("--out", default=str(ROOT / "_site"), help="output directory (site root)")
    ap.add_argument("--packages", help="read Arch packages from a JSON snapshot instead of the mirror")
    ap.add_argument("--osv-dir", help="read <Ecosystem>.zip exports from this directory instead of downloading")
    ap.add_argument("--aliases", default=str(ROOT / "aliases.json"))
    ap.add_argument("--dump-packages", help="also save the fetched package list here (input for --packages)")
    args = ap.parse_args(argv)

    if args.packages:
        snap = json.loads(Path(args.packages).read_text())
        packages = snap["packages"] if isinstance(snap, dict) else snap
        print(f"Arch packages from {args.packages}: {len(packages)}", flush=True)
    else:
        print("Fetching Arch repository databases...", flush=True)
        packages = []
        for repo in archrepo.REPOS:
            try:
                packages.extend(archrepo.fetch_repo_db(MIRROR, repo))
            except Exception as e:  # noqa: BLE001
                print(f"  WARNING: could not fetch {repo}: {e}", file=sys.stderr)
        print(f"  total packages: {len(packages)}", flush=True)
    if not packages:
        print("No packages fetched; refusing to write an empty feed.", file=sys.stderr)
        return 1
    if args.dump_packages:
        Path(args.dump_packages).write_text(json.dumps({"packages": packages}))

    aliases = names.load_aliases(Path(args.aliases))
    wanted: dict[str, set[str]] = {}
    for base, info in group_pkgbases(packages).items():
        up = upstream_version(split_arch(info["version"])[1])
        for fam, cands in names.candidates(base, up, aliases).items():
            wanted.setdefault(fam, set()).update(cands)

    print("Loading OSV.dev exports...", flush=True)
    index = osv.load_exports(ECOSYSTEMS, wanted, local_dir=Path(args.osv_dir) if args.osv_dir else None)
    feed = build(packages, index, aliases)
    if feed["stats"]["covered_pkgbases"] == 0:
        print("No pkgbase matched any record; refusing to write an empty feed.", file=sys.stderr)
        return 1

    out = Path(args.out)
    (out / "data").mkdir(parents=True, exist_ok=True)
    compact = {"separators": (",", ":"), "ensure_ascii": False}
    (out / "data" / "advisories.json").write_text(json.dumps(feed, **compact))
    (out / "all.json").write_text(json.dumps(arch_audit_feed(feed["pkgbases"]), **compact))
    s = feed["stats"]
    print(f"  verification: {s}", flush=True)
    print(f"Done. {s['covered_pkgbases']}/{s['pkgbases']} pkgbases have CVE records; "
          f"{s['vulnerable']} vulnerable, {s['unfixed']} unfixed (+{s['unfixed_minor']} unimportant), "
          f"{s['uncertain']} uncertain package/issue pairs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
