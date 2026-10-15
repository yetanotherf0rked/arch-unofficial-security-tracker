#!/usr/bin/env python3
"""
arch-cve-check: which known CVEs affect the packages installed on this Arch machine?

  arch-cve-check                  check this machine (`pacman -Q`)
  pacman -Q | arch-cve-check -    check a package list ("name version" lines)

Exit status: 0 nothing found, 1 affected (upgrade / vulnerable / unfixed),
3 only "uncertain" findings, 2 error. Standard library only; versions are
compared by pacman's own libalpm (`alpm_pkg_vercmp`).
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import gzip
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

FEED = os.environ.get(
    "ARCH_CVE_FEED", "https://yetanotherf0rked.github.io/arch-unofficial-security-tracker/data/advisories.json")

# --- versions -----------------------------------------------------------------

_alpm = ctypes.CDLL(ctypes.util.find_library("alpm") or "libalpm.so")
_alpm.alpm_pkg_vercmp.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
_alpm.alpm_pkg_vercmp.restype = ctypes.c_int


def vercmp(a: str, b: str) -> int:
    """pacman's ordering (libalpm): -1, 0 or 1."""
    r = _alpm.alpm_pkg_vercmp(a.encode(), b.encode())
    return (r > 0) - (r < 0)


def norm(v: str) -> str:
    """
    An upstream version written so that pacman's ordering compares Arch's and
    Debian's spellings of it correctly. Applied to both sides.
    """
    v = re.sub(r"^((?:19|20)\d\d)[._-]?(\d\d)[._-]?(\d\d)(?!\d)", r"\1\2\3", v)  # 2026_10_09 = 20261009
    v = re.sub(r"[-_.]stable$", "", v, flags=re.I)                              # libevent 2.1.13-stable
    v = re.sub(r"[-_.~]?(alpha|beta|pre|rc)(?=\d|$)", r"\1", v, flags=re.I)     # 1.0~rc1 = 1.0rc1 < 1.0
    v = v.replace("~", "").replace("-", ".").replace("_", ".")
    return re.sub(r"(?<=\d)\.?p(?=\d)", ".p", v)                                # 1.9.17p2 = 1.9.17.p2 > 1.9.17


def key(version: str) -> str:
    """Installed Arch version ("1:2.3-4") as compared with feed thresholds ("1:2.3")."""
    epoch, _, rest = version.rpartition(":")
    pkgver = rest.rsplit("-", 1)[0] if "-" in rest else rest
    return f"{epoch}:{norm(pkgver)}" if epoch else norm(pkgver)


def affects(version: str, issue: dict) -> bool:
    """Is this installed version affected? `fixed`: below it; `upto`: at or below it; neither: always."""
    if "fixed" in issue:
        return vercmp(key(version), issue["fixed"]) < 0
    if "upto" in issue:
        return vercmp(key(version), issue["upto"]) <= 0
    return True


# --- checking -----------------------------------------------------------------

GROUPS = {
    "upgrade": "Fixed in the repos: upgrade with `pacman -Syu`",
    "vulnerable": "Vulnerable: upstream has a fix, the Arch package does not have it yet",
    "unfixed": "Vulnerable: no upstream fix known",
    "uncertain": "Possibly affected: the sources do not cover this version",
}


def assess(installed: list[tuple[str, str]], feed: dict, minor: bool = False) -> dict:
    findings, foreign, nodata = [], [], []
    for name, version in installed:
        base = feed["packages"].get(name)
        if base is None:
            foreign.append(name)
            continue
        entry = feed["pkgbases"].get(base)
        if entry is None:
            nodata.append(name)
            continue
        groups: dict[str, list[dict]] = {}
        for issue in entry["issues"]:
            if (issue.get("minor") and not minor) or not affects(version, issue):
                continue
            group = "upgrade" if issue["status"] == "fixed" else issue["status"]
            groups.setdefault(group, []).append(issue)
        for group, issues in groups.items():
            fixes = sorted({i["fixed"] for i in issues if "fixed" in i}, key=_Key)
            findings.append({"package": name, "version": version, "group": group, "repo": entry["version"],
                             "fixed": fixes[-1] if fixes else None, "issues": [i["id"] for i in issues]})
    order = list(GROUPS)
    findings.sort(key=lambda f: (order.index(f["group"]), f["package"]))
    return {"findings": findings, "foreign": foreign, "nodata": nodata, "checked": len(installed)}


class _Key(str):
    def __lt__(self, other: str) -> bool:
        return vercmp(self, other) < 0


def exit_status(result: dict, upgradable: bool = False) -> int:
    groups = {f["group"] for f in result["findings"]}
    if groups & ({"upgrade"} if upgradable else {"upgrade", "vulnerable", "unfixed"}):
        return 1
    return 3 if not upgradable and "uncertain" in groups else 0


# --- input / output -----------------------------------------------------------

def load_feed(src: str) -> dict:
    if src.startswith(("http://", "https://")):
        req = urllib.request.Request(src, headers={"User-Agent": "arch-cve-check", "Accept-Encoding": "gzip"})
        with urllib.request.urlopen(req, timeout=60) as r:
            body = r.read()
    else:
        with open(src, "rb") as f:
            body = f.read()
    return json.loads(gzip.decompress(body) if body[:2] == b"\x1f\x8b" else body)


def parse_list(text: str) -> list[tuple[str, str]]:
    return [(p[0], p[1]) for p in (line.split() for line in text.splitlines()) if len(p) >= 2]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="arch-cve-check", description=__doc__.strip().splitlines()[0])
    ap.add_argument("list", nargs="?", help="`pacman -Q` output file, '-' for stdin (default: run pacman -Q)")
    ap.add_argument("--feed", default=FEED)
    ap.add_argument("-a", "--all", action="store_true", help="include issues Debian rates unimportant")
    ap.add_argument("-u", "--upgradable", action="store_true", help="only issues an upgrade fixes")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print affected package names")
    ap.add_argument("-v", "--verbose", action="store_true", help="list every CVE and the unchecked packages")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    try:
        if args.list == "-":
            text = sys.stdin.read()
        elif args.list:
            text = open(args.list).read()
        else:
            text = subprocess.run(["pacman", "-Q"], capture_output=True, text=True, check=True).stdout
        feed = load_feed(args.feed)
    except Exception as e:  # noqa: BLE001
        print(f"arch-cve-check: {e}", file=sys.stderr)
        return 2
    age = time.time() - feed["generated_at"]
    if age > 3 * 86400:
        print(f"arch-cve-check: warning: the feed is {int(age // 86400)} days old", file=sys.stderr)

    res = assess(parse_list(text), feed, args.all)
    if args.upgradable:
        res["findings"] = [f for f in res["findings"] if f["group"] == "upgrade"]
    if args.json:
        print(json.dumps(res, indent=1))
    elif args.quiet:
        for name in dict.fromkeys(f["package"] for f in res["findings"]):
            print(name)
    else:
        print(f"Checked {res['checked']} packages against the feed of "
              f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(feed['generated_at']))}.")
        for group, title in GROUPS.items():
            rows = [f for f in res["findings"] if f["group"] == group]
            if rows:
                print(f"\n{title} ({len(rows)} packages)")
            for f in rows:
                fix = f" -> {f['repo']}" if group == "upgrade" else f"  (fixed in {f['fixed']})" if f["fixed"] else ""
                ids = f["issues"] if args.verbose else f["issues"][:4] + ([f"+{len(f['issues']) - 4} more"] if len(f["issues"]) > 4 else [])
                print(f"  {f['package']} {f['version']}{fix}\n      {' '.join(ids)}")
        if not res["findings"]:
            print("No known CVE affects the installed versions of the covered packages.")
        print(f"\nNot checked: {len(res['nodata'])} packages without CVE data, {len(res['foreign'])} not from the repos."
              + ("" if args.verbose else " -v lists them."))
        if args.verbose:
            print("  no data: " + " ".join(res["nodata"]) + "\n  foreign: " + " ".join(res["foreign"]))
    return exit_status(res, args.upgradable)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:  # output piped into e.g. `head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
