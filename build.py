#!/usr/bin/env python3
"""
Build the tracker feed.

  Arch repos          `expac -S` on pacman's sync databases (run `pacman -Sy` first;
                      PACMAN_CONF selects another pacman.conf, e.g. one with multilib)
  userland CVEs       Debian security tracker JSON (every Debian release, including sid);
                      Debian's apt Sources index (homepages) to match differently named packages
  kernel CVEs         the kernel CNA's records (git clone of linux/security/vulns.git)

Writes OUT/data/advisories.json (read by arch-cve-check and the page) and
OUT/all.json (security.archlinux.org's format, for `arch-audit --source`).
Versions are compared by libalpm; see arch_cve_check.norm for the spelling rules.
"""

from __future__ import annotations

import argparse
import glob
import json
import lzma
import os
import re
import subprocess
import sys
import time
import urllib.request

from arch_cve_check import key, norm, vercmp

DEBIAN_JSON = "https://security-tracker.debian.org/tracker/data/json"
KERNEL_GIT = "https://git.kernel.org/pub/scm/linux/security/vulns.git"
KERNELS = {"linux", "linux-lts", "linux-zen", "linux-hardened", "linux-rt", "linux-rt-lts"}
ALIASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aliases.json")


# --- Arch ---------------------------------------------------------------------

def arch_packages() -> list[dict]:
    """Every package in the sync databases pacman knows (core, extra, multilib)."""
    conf = ["--config", os.environ["PACMAN_CONF"]] if os.environ.get("PACMAN_CONF") else []
    out = subprocess.run(["expac", *conf, "-S", "%r\t%n\t%e\t%v\t%u"], capture_output=True, text=True, check=True).stdout
    pkgs = [dict(zip(("repo", "name", "base", "version", "url"), line.split("\t"))) for line in out.splitlines()]
    repos = {p["repo"] for p in pkgs}
    if not {"core", "extra", "multilib"} <= repos:
        sys.exit(f"sync databases incomplete ({sorted(repos)}); refusing to build a partial feed")
    return pkgs


# --- Debian -------------------------------------------------------------------

def deb_upstream(v: str) -> str:
    """Debian version -> normalized upstream version ("1:2.3+dfsg-4" -> "2.3")."""
    v = v.split(":", 1)[-1]
    v = v.rsplit("-", 1)[0] if "-" in v else v
    v = re.sub(r"^.*[+~]really", "", v)
    v = re.sub(r"[+~](?:dfsg|ds|repack|deb\d|nmu|ubuntu)[\w.+~]*$", "", v, flags=re.I)
    return norm(v)


def new_upstream(v: str) -> bool:
    """Does this Debian upload import an upstream release (-1, -0.1, -1~bpo…), rather than patch one?"""
    v = v.split(":", 1)[-1]
    if re.search(r"[+~]really", v):
        return False  # a downgrade ("5.6.1+really5.4.5"): the outer version is the vulnerable one
    return "-" not in v or bool(re.match(r"(?:0(?:\.\d+)?|1)(?:~.*)?$|0\+deb\d+u\d+$", v.rsplit("-", 1)[1]))


def branch(v: str) -> tuple[str, ...]:
    return tuple(re.findall(r"\d+", v)[:2])


def deb_patched(v: str) -> str:
    """The upstream version a Debian patch upload fixed; for "5.6.1+really5.4.5" that is 5.6.1."""
    m = re.match(r"(?:\d+:)?(.*?)[+~]really", v)
    return norm(m.group(1)) if m else deb_upstream(v)


def evaluate(a: str, rec: dict, recent: bool = False) -> dict | None:
    """
    Arch's normalized upstream version `a` against Debian's record of one CVE.
    Returns {"status", and "fixed" (affected below) or "upto" (affected at or
    below)} or None when Arch's version is not affected. `recent`: the CVE is
    from this or last year.
    """
    rels = rec["releases"]
    fixes, open_versions = [], set()
    for r in rels.values():
        f = r.get("fixed_version")
        if r["status"] == "resolved" and f and f != "0" and new_upstream(f):
            fixes.append(deb_upstream(f))
        if r["status"] == "open":
            open_versions |= {deb_upstream(v) for v in r["repositories"].values()}
    above = sorted((f for f in fixes if vercmp(a, f) < 0), key=lambda f: (branch(f) != branch(a), _K(f)))
    nxt = {"fixed": above[0]} if above else {}

    # Debian ships this exact upstream version and calls it vulnerable.
    if a in open_versions:
        return {"status": "vulnerable", **nxt} if nxt else {"status": "unfixed"}
    # An upstream release on Arch's own line has the fix.
    own = [f for f in fixes if branch(f) == branch(a) and vercmp(a, f) >= 0]
    if own:
        return {"status": "fixed", "fixed": min(own, key=_K)}

    sid = rels.get("sid") or rels[max(rels)]
    if sid["status"] == "resolved":
        f = sid.get("fixed_version") or "0"
        if f == "0":
            return None  # Debian: not affected
        u = deb_upstream(f)
        if new_upstream(f):
            return {"status": "fixed", "fixed": u} if vercmp(a, u) >= 0 else {"status": "vulnerable", **(nxt or {"fixed": u})}
        # A Debian patch on upstream u: u is vulnerable. Whether releases after u
        # have the fix is unknown; for recent CVEs only Arch's current version
        # counts as fixed, older ones assume the next release had it.
        u = deb_patched(f)
        if vercmp(a, u) <= 0:
            return {"status": "unfixed", "upto": u}
        return {"status": "fixed", "fixed": a} if recent else {"status": "fixed", "upto": u}
    if sid["status"] == "open":
        d = max((deb_upstream(v) for v in sid["repositories"].values()), key=_K)
        return {"status": "unfixed" if vercmp(a, d) <= 0 else "uncertain"}
    return {"status": "uncertain"}


class _K(str):
    def __lt__(self, other: str) -> bool:
        return vercmp(self, other) < 0


def site(url: str) -> str:
    """Project identity of a homepage: host, plus owner/repo on forges."""
    u = re.sub(r"^\w+://(www\.)?", "", url.lower()).rstrip("/")
    host, *path = u.split("/")
    if host in ("github.com", "gitlab.com", "codeberg.org", "sourceforge.net", "pypi.org", "metacpan.org") or host.startswith("gitlab."):
        return "/".join([host, *path[:2]]).removesuffix(".git")
    return host


def debian_source(base: str, upstream: str, url: str, debian: dict, aliases: dict, sid: dict, homepage: dict,
                  arch_bases: set) -> str | None:
    """
    The Debian source package that builds the same project as this Arch pkgbase:
    an alias, else the same name, else (python-foo: foo, python-foo; perl-foo:
    libfoo-perl; foo: python-foo, foo2, libfoo-1.0, …) a name whose Debian
    homepage is Arch's and, if it names a release line ("ruby3.3"), Arch's line.
    """
    name = base.removeprefix("lib32-")
    nums = re.findall(r"\d+", upstream)
    if name in aliases:
        fmt = {"major": nums[0] if nums else "", "minor": nums[1] if len(nums) > 1 else ""}
        return next((s for s in (a.format(**fmt) for a in aliases[name]) if s in debian), None)
    if name in debian:
        # Same name, different project (Arch's keystone 0.9 vs OpenStack keystone 22+).
        m = re.findall(r"\d+", sid.get(name, ""))
        return None if nums and m and int(m[0]) > 2 * int(nums[0]) + 1 else name
    short = name.removeprefix("python-").removeprefix("perl-")
    if name.startswith("perl-"):
        cands = [f"lib{short}-perl"]
    elif name.startswith("python-"):
        cands = [f"python-{short}", short]
    else:
        versioned = re.compile(rf"(?:lib)?{re.escape(name)}-?(\d[\d.]*)")
        cands = [f"python-{name}"] + [s for s in sorted(debian) if versioned.fullmatch(s) and s not in arch_bases]
    for c in cands:
        # A versioned name must be Arch's release line: "ruby3.3" needs Arch 3.3.x, "musescore2" Arch 2.x.
        line = re.fullmatch(rf"(?:lib)?{re.escape(name)}-?(\d[\d.]*)", c)
        if line and not (upstream.startswith(line.group(1) + ".") or (line.group(1).isdigit()
                         and (re.findall(r"\d+", sid.get(c, "")) or [""])[0] == (nums or [""])[0])):
            continue
        if c in debian and site(homepage.get(c, "")) == site(url):
            return c
    return None


def debian_homepages() -> dict:
    """Debian source -> Homepage, from sid's apt Sources indexes."""
    out = {}
    for comp in ("main", "contrib", "non-free"):
        url = f"https://deb.debian.org/debian/dists/sid/{comp}/source/Sources.xz"
        with urllib.request.urlopen(url, timeout=300) as r:
            text = lzma.decompress(r.read()).decode("utf-8", "replace")
        for stanza in text.split("\n\n"):
            pkg, home = re.search(r"^Package: (.+)$", stanza, re.M), re.search(r"^Homepage: (.+)$", stanza, re.M)
            if pkg and home:
                out[pkg.group(1)] = home.group(1).strip()
    return out


# --- kernel -------------------------------------------------------------------

def kernel_records(path: str) -> list[tuple[str, str, list[dict]]]:
    """(CVE, summary, version rules) from the kernel CNA's records."""
    out = []
    for f in glob.glob(os.path.join(path, "cve", "published", "*", "*.json")):
        with open(f) as fh:
            cna = json.load(fh)["containers"]["cna"]
        rules = next((a["versions"] for a in cna.get("affected", []) if a.get("defaultStatus") == "affected"), None)
        if rules:
            text = (cna.get("descriptions") or [{}])[0].get("value", "")
            out.append((os.path.basename(f)[:-5], text.split("resolved:", 1)[-1].strip(), rules))
    return out


def kernel_evaluate(k: str, rules: list[dict]) -> dict | None:
    """The CNA's rules for upstream kernel `k`: introduced in X; fixed in X on line L.*; fixed in mainline X."""
    line = ".".join(k.split(".")[:2])
    line_fix = mainline = None
    for r in rules:
        if r.get("status") != "unaffected" or r.get("versionType") == "git":
            continue
        if r["version"] == "0" and r.get("lessThan") and vercmp(k, norm(r["lessThan"])) < 0:
            return None  # before the bug was introduced
        if r.get("lessThanOrEqual") == f"{line}.*":
            line_fix = norm(r["version"])
        elif r.get("lessThanOrEqual") == "*":
            mainline = norm(r["version"])
    fix = line_fix or (mainline if mainline and vercmp(k, mainline) >= 0 else None)
    if fix:
        return {"status": "fixed" if vercmp(k, fix) >= 0 else "vulnerable", "fixed": fix}
    return {"status": "vulnerable" if mainline else "unfixed"}  # fixed only on newer lines, or not at all


# --- feed ---------------------------------------------------------------------

def build(pkgs: list[dict], debian: dict, kernel: list, aliases: dict, homepage: dict) -> dict:
    sid = {src: deb_upstream(r["repositories"]["sid"]) for src, cves in debian.items() for rec in cves.values()
           for r in [rec["releases"].get("sid")] if r and r["repositories"].get("sid")}
    bases: dict[str, dict] = {}
    for p in pkgs:
        b = bases.setdefault(p["base"], {"version": p["version"], "repo": p["repo"], "url": p["url"], "packages": []})
        b["packages"].append(p["name"])
    feed: dict = {"schema": 2, "generated_at": int(time.time()), "packages": {p["name"]: p["base"] for p in pkgs},
                  "pkgbases": {}, "cves": {}}
    for base, b in sorted(bases.items()):
        epoch, _, rest = b["version"].rpartition(":")
        a = key(rest)
        issues = []
        if base in KERNELS:
            k = re.match(r"\d+\.\d+(?:\.\d+)?", a)
            for cve, text, rules in kernel if k else []:
                v = kernel_evaluate(k.group(0), rules)
                if v:
                    issues.append({"id": cve, **v})
                    if v["status"] != "fixed":
                        feed["cves"][cve] = text[:200]
            b["source"] = "kernel CNA"
        elif src := debian_source(base, a, b["url"], debian, aliases, sid, homepage, set(bases)):
            for cve, rec in debian[src].items():
                recent = int(cve.split("-")[1]) >= time.gmtime().tm_year - 1 if cve.startswith("CVE-") else False
                if not cve.startswith("CVE-") or not (v := evaluate(a, rec, recent)):
                    continue
                urgency = (rec["releases"].get("sid") or {}).get("urgency", "")
                issue = {"id": cve, **v, **({"minor": True} if urgency == "unimportant" else {})}
                issues.append(issue)
                if v["status"] != "fixed":
                    feed["cves"][cve] = (rec.get("description") or "")[:200]
            b["source"] = f"Debian {src}"
        else:
            continue
        for i in issues:  # thresholds carry Arch's epoch, like installed versions do
            for t in ("fixed", "upto"):
                if t in i and epoch:
                    i[t] = f"{epoch}:{i[t]}"
        b["issues"] = sorted(issues, key=lambda i: i["id"], reverse=True)
        feed["pkgbases"][base] = b
    count = lambda st: sum(1 for b in feed["pkgbases"].values() for i in b["issues"] if i["status"] == st and not i.get("minor"))  # noqa: E731
    feed["stats"] = {"pkgbases": len(bases), "covered": len(feed["pkgbases"]),
                     **{st: count(st) for st in ("vulnerable", "unfixed", "uncertain")}}
    return feed


def arch_audit(feed: dict) -> list[dict]:
    """Open issues in security.archlinux.org's all.json format (arch-audit lists them when installed)."""
    out = []
    for base, b in feed["pkgbases"].items():
        for st, label in (("vulnerable", "Vulnerable"), ("unfixed", "Vulnerable"), ("uncertain", "Unknown")):
            ids = [i["id"] for i in b["issues"] if i["status"] == st and not i.get("minor")]
            if ids:
                out.append({"name": f"UAVG-{base}-{st}", "packages": b["packages"], "status": label,
                            "severity": "Unknown", "type": "possible security issues" if st == "uncertain" else "security issues",
                            "affected": b["version"], "fixed": None,
                            "ticket": None, "issues": ids, "advisories": []})
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--out", default="_site")
    ap.add_argument("--debian", help="Debian tracker JSON file instead of downloading it")
    ap.add_argument("--homepages", help="JSON {debian source: homepage} instead of reading Debian's Sources")
    ap.add_argument("--kernel", default="vulns", help="checkout of the kernel CNA repo (cloned if missing)")
    args = ap.parse_args()
    if args.debian:
        with open(args.debian, "rb") as f:
            debian = json.load(f)
    else:
        with urllib.request.urlopen(urllib.request.Request(DEBIAN_JSON, headers={"User-Agent": "arch-cve-tracker"}), timeout=300) as r:
            debian = json.load(r)
    if not os.path.isdir(args.kernel):
        subprocess.run(["git", "clone", "--quiet", "--depth", "1", KERNEL_GIT, args.kernel], check=True)
    with open(ALIASES) as f:
        aliases = {k: v for k, v in json.load(f).items() if not k.startswith("_")}
    homepage = json.load(open(args.homepages)) if args.homepages else debian_homepages()
    feed = build(arch_packages(), debian, kernel_records(args.kernel), aliases, homepage)
    os.makedirs(os.path.join(args.out, "data"), exist_ok=True)
    with open(os.path.join(args.out, "data", "advisories.json"), "w") as f:
        json.dump(feed, f, separators=(",", ":"))
    with open(os.path.join(args.out, "all.json"), "w") as f:
        json.dump(arch_audit(feed), f, separators=(",", ":"))
    print(json.dumps(feed["stats"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
