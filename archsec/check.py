#!/usr/bin/env python3
"""
arch-cve-check — am I affected? Compares the packages installed on this
machine with the unofficial Arch security tracker's feed.

Usage:
  arch-cve-check                      check this machine (reads the pacman DB)
  pacman -Q | arch-cve-check -        check a package list ("name version" lines)
  arch-cve-check --json               machine-readable output

Exit status: 1 when an installed package is affected (upgradable,
vulnerable or unfixed), 0 otherwise (also when only uncertain matches are
listed), 2 on error. Only the Python standard library is needed. This file is
self-contained on purpose: it is published as a single script.
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Iterable

DEFAULT_FEED = os.environ.get(
    "ARCH_CVE_FEED",
    "https://yetanotherf0rked.github.io/arch-unofficial-security-tracker/data/advisories.json",
)
STALE_AFTER = 3 * 86400  # warn when the feed is older than this

# ---------------------------------------------------------------------------
# pacman's version ordering (port of libalpm's alpm_pkg_vercmp / rpmvercmp)
# ---------------------------------------------------------------------------

_DIGITS = frozenset("0123456789")
_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_ALNUM = _DIGITS | _ALPHA


def _rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    la, lb = len(a), len(b)
    one = two = p1 = p2 = 0
    while one < la and two < lb:
        while one < la and a[one] not in _ALNUM:
            one += 1
        while two < lb and b[two] not in _ALNUM:
            two += 1
        if not (one < la and two < lb):
            break
        # Different separator lengths decide on their own.
        if one - p1 != two - p2:
            return -1 if one - p1 < two - p2 else 1
        p1, p2 = one, two
        if a[p1] in _DIGITS:
            while p1 < la and a[p1] in _DIGITS:
                p1 += 1
            while p2 < lb and b[p2] in _DIGITS:
                p2 += 1
            isnum = True
        else:
            while p1 < la and a[p1] in _ALPHA:
                p1 += 1
            while p2 < lb and b[p2] in _ALPHA:
                p2 += 1
            isnum = False
        s1, s2 = a[one:p1], b[two:p2]
        if not s2:  # numeric segments are always newer than alpha ones
            return 1 if isnum else -1
        if isnum:
            s1, s2 = s1.lstrip("0"), s2.lstrip("0")
            if len(s1) != len(s2):
                return 1 if len(s1) > len(s2) else -1
        if s1 != s2:
            return -1 if s1 < s2 else 1
        one, two = p1, p2
    if one >= la and two >= lb:
        return 0
    # A remaining alpha string never beats an empty one ("1.0rc" < "1.0").
    if (one >= la and not (two < lb and b[two] in _ALPHA)) or (one < la and a[one] in _ALPHA):
        return -1
    return 1


def _parse_evr(v: str) -> tuple[str, str, str | None]:
    i = 0
    while i < len(v) and v[i] in _DIGITS:
        i += 1
    dash = v.rfind("-", i)
    if i < len(v) and v[i] == ":":
        epoch, start = v[:i] or "0", i + 1
    else:
        epoch, start = "0", 0
    if dash != -1:
        return epoch, v[start:dash], v[dash + 1:]
    return epoch, v[start:], None


def vercmp(a: str, b: str) -> int:
    """pacman's `vercmp`: -1, 0 or 1. A missing pkgrel on either side is ignored."""
    if a == b:
        return 0
    e1, v1, r1 = _parse_evr(a)
    e2, v2, r2 = _parse_evr(b)
    ret = _rpmvercmp(e1, e2)
    if ret == 0:
        ret = _rpmvercmp(v1, v2)
        if ret == 0 and r1 is not None and r2 is not None:
            ret = _rpmvercmp(r1, r2)
    return ret


# ---------------------------------------------------------------------------
# Installed packages
# ---------------------------------------------------------------------------

def read_local_db(dbpath: Path) -> list[dict[str, str]]:
    """Installed packages from pacman's local DB: [{name, version, base}]."""
    local = dbpath / "local"
    if not local.is_dir():
        raise FileNotFoundError(f"no pacman local database at {local}")
    out = []
    for desc in sorted(local.glob("*/desc")):
        fields: dict[str, str] = {}
        key = None
        for line in desc.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("%") and line.endswith("%") and len(line) > 2:
                key = line.strip("%")
            elif key and line:
                fields.setdefault(key, line)
            else:
                key = None
        if "NAME" in fields and "VERSION" in fields:
            out.append({
                "name": fields["NAME"], "version": fields["VERSION"],
                "base": fields.get("BASE", fields["NAME"]),
            })
    return out


def read_package_list(lines: Iterable[str]) -> list[dict[str, str]]:
    """`pacman -Q` output ("name version" per line)."""
    out = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and not line.startswith("#"):
            out.append({"name": parts[0], "version": parts[1], "base": ""})
    return out


# ---------------------------------------------------------------------------
# Feed
# ---------------------------------------------------------------------------

def load_feed(source: str) -> dict[str, Any]:
    if source.startswith(("http://", "https://")):
        req = urllib.request.Request(source, headers={
            "User-Agent": "arch-cve-check", "Accept-Encoding": "gzip",
        })
        with urllib.request.urlopen(req, timeout=60) as r:
            body = r.read()
            if r.headers.get("Content-Encoding") == "gzip":
                body = gzip.decompress(body)
    else:
        body = Path(source).read_bytes()
        if body[:2] == b"\x1f\x8b":
            body = gzip.decompress(body)
    return json.loads(body)


SEVERITIES = ["Unknown", "Low", "Medium", "High", "Critical"]

# How a finding is presented, most urgent first.
GROUPS = {
    "upgrade": "Fixed in the Arch repos — upgrade with `pacman -Syu`",
    "vulnerable": "Vulnerable — upstream has a fix, Arch does not ship it yet",
    "unfixed": "Vulnerable — no fix released upstream yet",
    "uncertain": "Possibly affected — version comparison not conclusive",
}


def assess(installed: list[dict[str, str]], feed: dict[str, Any], include_minor: bool = False) -> dict[str, Any]:
    """
    Match installed packages against the feed. Returns
    {"findings": [...], "foreign": [...], "uncovered": [...], "checked": n}.
    A finding is one installed package and one group of issues concerning it.

    Thresholds in the feed are Arch versions:
      - feed["pkgbases"][base]["fixed"]: [{"fixed": v, "ids": [...]}] — the
        repos have the fix; installed versions below v are affected;
      - feed["pkgbases"][base]["issues"]: issues the repo version still has;
        an optional "fixed" there is the upstream fix written as an Arch
        version (a newer installed build, e.g. from [testing], may have it).
    """
    repo_pkgs: dict[str, str] = feed.get("packages", {})
    bases: dict[str, Any] = feed.get("pkgbases", {})
    findings, foreign, uncovered = [], [], []
    for pkg in installed:
        name, version = pkg["name"], pkg["version"]
        if name not in repo_pkgs:
            foreign.append(name)
            continue
        base = pkg.get("base") or repo_pkgs[name]
        entry = bases.get(base) or bases.get(repo_pkgs[name])
        if not entry:
            uncovered.append(name)
            continue
        hits: dict[str, list[dict[str, Any]]] = {}
        for group in entry.get("fixed", []):
            if vercmp(version, group["fixed"]) < 0:
                for cid in group["ids"]:
                    hits.setdefault("upgrade", []).append(
                        {"id": cid, "fixed": group["fixed"], "severity": group.get("severity", "Unknown")})
        for issue in entry.get("issues", []):
            if issue.get("minor") and not include_minor:
                continue
            fixed = issue.get("fixed")
            if not (fixed and vercmp(version, fixed) >= 0):
                hits.setdefault(issue["status"], []).append(issue)
        for group, issues in hits.items():
            sev = max((SEVERITIES.index(i.get("severity", "Unknown")) for i in issues), default=0)
            fixes = sorted({i["fixed"] for i in issues if i.get("fixed")}, key=_cmp_key)
            findings.append({
                "package": name, "version": version, "base": base, "group": group,
                "repo_version": entry.get("version"),
                "severity": SEVERITIES[sev],
                "fixed": fixes[-1] if fixes else None,
                "upstream_fix": sorted({f for i in issues for f in i.get("fix", [])}, key=_cmp_key),
                "issues": [i["id"] for i in issues],
                "reasons": sorted({i["reason"] for i in issues if i.get("reason")}),
            })
    order = list(GROUPS)
    findings.sort(key=lambda f: (order.index(f["group"]), -SEVERITIES.index(f["severity"]), f["package"]))
    return {"findings": findings, "foreign": foreign, "uncovered": uncovered, "checked": len(installed)}


class _Key:
    __slots__ = ("v",)

    def __init__(self, v: str) -> None:
        self.v = v

    def __lt__(self, other: "_Key") -> bool:
        return vercmp(self.v, other.v) < 0


def _cmp_key(v: str) -> _Key:
    return _Key(v)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

REASONS = {
    "below-fix": "below the upstream fix",
    "distro-patch": "other distros patched this exact version",
    "no-fix": "no upstream fix yet",
    "between-branches": "Arch's release line may not have the fix",
    "arch-snapshot": "Arch builds a VCS snapshot",
    "fix-snapshot": "the fix is an unreleased snapshot",
    "version-scheme": "version schemes differ",
    "distro-patch-rebuilt": "other distros patched this exact version; Arch rebuilt since and might carry the patch",
    "patch-only": "fixed only by distro patches, no upstream release",
    "newer-than-assessed": "reported unfixed for older versions; Arch's newer one is unassessed",
}


def _color(enabled: bool):
    codes = {"Critical": "1;31", "High": "31", "Medium": "33", "Low": "36", "Unknown": "37", "bold": "1", "dim": "2"}

    def paint(text: str, what: str) -> str:
        return f"\033[{codes[what]}m{text}\033[0m" if enabled and what in codes else text
    return paint


def _ago(seconds: float) -> str:
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if seconds < 172800:
        return f"{int(seconds // 3600)} h ago"
    return f"{int(seconds // 86400)} days ago"


def render(result: dict[str, Any], feed: dict[str, Any], args: argparse.Namespace, out=None) -> None:
    out = out or sys.stdout
    paint = _color(args.color)
    findings = result["findings"]
    if args.upgradable:
        findings = [f for f in findings if f["group"] == "upgrade"]
    if args.quiet:
        for f in findings:
            print(f["package"] + (f">={f['fixed']}" if f["group"] == "upgrade" and f["fixed"] else ""), file=out)
        return

    gen = feed.get("generated_at", 0)
    print(paint(f"Checked {result['checked']} packages against the feed from "
                f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(gen))} ({_ago(time.time() - gen)}).", "dim"), file=out)
    if not findings:
        print(paint("No known CVE affects the installed versions of the covered packages.", "bold"), file=out)
    for group, title in GROUPS.items():
        rows = [f for f in findings if f["group"] == group]
        if not rows:
            continue
        n_cves = len({i for f in rows for i in f["issues"]})
        print(f"\n{paint(title, 'bold')}  ({len(rows)} packages, {n_cves} CVEs)", file=out)
        for f in rows:
            sev = paint(f"{f['severity']:<8}", f["severity"])
            if group == "upgrade":
                what = f"{f['version']} -> {f['repo_version']}  (fixed in {f['fixed']})"
            elif f["upstream_fix"] and group == "vulnerable":
                what = f"{f['version']}  (upstream fix: {', '.join(f['upstream_fix'][:3])})"
            else:
                what = f["version"]
            print(f"  {sev} {paint(f['package'], 'bold')} {what}", file=out)
            ids = f["issues"]
            if args.show_cve:
                print(f"           {' '.join(ids)}", file=out)
            else:
                more = f" +{len(ids) - 3} more" if len(ids) > 3 else ""
                print(paint(f"           {' '.join(ids[:3])}{more}", "dim"), file=out)
            if group in ("uncertain", "vulnerable") and f["reasons"]:
                notes = "; ".join(REASONS.get(r, r) for r in f["reasons"])
                print(paint(f"           why: {notes}", "dim"), file=out)

    notes = []
    if result["foreign"]:
        notes.append(f"{len(result['foreign'])} not from the official repos (AUR/local) — not checked")
    if result["uncovered"]:
        notes.append(f"{len(result['uncovered'])} with no CVE records in the tracker's sources — not checked")
    if notes:
        print(paint("\nCoverage: " + "; ".join(notes) + ". Use --list-unchecked to see them.", "dim"), file=out)
    if args.list_unchecked:
        for label, names in (("foreign", result["foreign"]), ("no data", result["uncovered"])):
            if names:
                print(f"  {label}: {' '.join(names)}", file=out)
    if not args.all:
        print(paint("Issues Debian rates 'unimportant' are hidden; --all shows them.", "dim"), file=out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="arch-cve-check", description=__doc__.split("\n\n")[0])
    ap.add_argument("packages", nargs="?", help="file with `pacman -Q` output ('-' for stdin) instead of the local DB")
    ap.add_argument("--feed", default=DEFAULT_FEED, help="feed URL or file (default: %(default)s)")
    ap.add_argument("-b", "--dbpath", default="/var/lib/pacman", help="pacman database path")
    ap.add_argument("-a", "--all", action="store_true", help="include issues Debian rates 'unimportant'")
    ap.add_argument("-u", "--upgradable", action="store_true", help="only issues an upgrade fixes")
    ap.add_argument("-c", "--show-cve", action="store_true", help="list every CVE")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print affected package names")
    ap.add_argument("--json", action="store_true", help="print JSON")
    ap.add_argument("--list-unchecked", action="store_true", help="list packages the feed can't check")
    ap.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    args = ap.parse_args(argv)
    args.color = args.color == "always" or (args.color == "auto" and sys.stdout.isatty() and not os.environ.get("NO_COLOR"))

    try:
        if args.packages == "-":
            installed = read_package_list(sys.stdin)
        elif args.packages:
            installed = read_package_list(Path(args.packages).read_text().splitlines())
        else:
            installed = read_local_db(Path(args.dbpath))
        feed = load_feed(args.feed)
    except Exception as e:  # noqa: BLE001 — report any I/O or parse failure plainly
        print(f"arch-cve-check: {e}", file=sys.stderr)
        return 2

    if time.time() - feed.get("generated_at", 0) > STALE_AFTER:
        print(f"arch-cve-check: warning: the feed is {_ago(time.time() - feed.get('generated_at', 0))} old",
              file=sys.stderr)
    result = assess(installed, feed, include_minor=args.all)
    if args.json:
        json.dump({**result, "feed_generated_at": feed.get("generated_at")}, sys.stdout, indent=1)
        print()
    else:
        render(result, feed, args)
    definite = ("upgrade",) if args.upgradable else ("upgrade", "vulnerable", "unfixed")
    return 1 if any(f["group"] in definite for f in result["findings"]) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:  # output piped into e.g. `head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
