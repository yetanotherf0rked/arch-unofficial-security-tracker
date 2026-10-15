#!/usr/bin/env python3
"""
Build the tracker feed.

  Arch repos          `expac -S` on pacman's sync databases (run `pacman -Sy` first;
                      PACMAN_CONF selects another pacman.conf, e.g. one with multilib)
  userland CVEs       Debian security tracker JSON (every Debian release, including sid);
                      Debian's apt Sources index (homepages) to match differently named packages
  kernel CVEs         the kernel CNA's records (git clone of linux/security/vulns.git)
  Firefox/Thunderbird Mozilla's CVE records (CVE Services API), for what Debian leaves open
  Arch's own patches  CVE IDs in packaging releases (gitlab.archlinux.org: packaging/state,
                      then only the released packages' tags)
  first fixed build   carried over from the previously published feed

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
from concurrent.futures import ThreadPoolExecutor

from arch_cve_check import FEED, key, load_feed, norm, vercmp

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


def cna_evaluate(k: str, rules: list[dict], newer_line_fixes: bool = False) -> dict | None:
    """
    A CNA's version rules for upstream version `k`: unaffected below X
    (introduced); fixed in X on line "L.*"; fixed in X and later ("*").
    The kernel's "*" fix is on a newer line than an LTS kernel can move to;
    Mozilla's is the next release (`newer_line_fixes`).
    """
    line_fix = mainline = None
    for r in rules:
        if r.get("status") != "unaffected" or r.get("versionType") == "git":
            continue
        le = r.get("lessThanOrEqual") or ""
        if r["version"] == "0" and r.get("lessThan") and vercmp(k, norm(r["lessThan"])) < 0:
            return None  # before the bug was introduced
        if le.endswith(".*") and k.startswith(le[:-1]):
            line_fix = norm(r["version"])
        elif le == "*":
            mainline = norm(r["version"])
    fix = line_fix or (mainline if mainline and (newer_line_fixes or vercmp(k, mainline) >= 0) else None)
    if fix:
        return {"status": "fixed" if vercmp(k, fix) >= 0 else "vulnerable", "fixed": fix}
    return {"status": "vulnerable" if mainline else "unfixed"}  # fixed only on newer lines, or not at all


# --- Mozilla ------------------------------------------------------------------

MOZILLA = {"firefox": "Firefox", "thunderbird": "Thunderbird"}  # Arch pkgbase -> Mozilla product
CVE_API = "https://cveawg.mitre.org/api/cve/{}"


def mozilla_rules(feed: dict) -> dict:
    """{(pkgbase, CVE): version rules} from Mozilla's CVE records, for issues Debian leaves open."""
    want = [(b, i["id"]) for b in MOZILLA if b in feed["pkgbases"]
            for i in feed["pkgbases"][b]["issues"] if i["status"] != "fixed"]

    def fetch(item):
        req = urllib.request.Request(CVE_API.format(item[1]), headers={"User-Agent": "arch-cve-tracker"})
        with urllib.request.urlopen(req, timeout=60) as r:
            cna = json.load(r)["containers"]["cna"]
        return item, next((a.get("versions", []) for a in cna.get("affected", []) if a.get("product") == MOZILLA[item[0]]), None)

    with ThreadPoolExecutor(8) as pool:
        return {item: rules for item, rules in pool.map(fetch, want) if rules}


# --- Arch packaging -----------------------------------------------------------

STATE_GIT = "https://gitlab.archlinux.org/archlinux/packaging/state.git"
ARCH_GIT = "https://gitlab.archlinux.org/archlinux/packaging/packages/{}.git"
GIT = ["git", "-c", "http.userAgent=arch-cve-tracker (+https://github.com/yetanotherf0rked/arch-unofficial-security-tracker)"]
FETCH_MINUTES = float(os.environ.get("FETCH_MINUTES", "10"))  # time spent fetching packaging repos per run
_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def gitlab_path(name: str) -> str:
    """pkgbase -> project path on gitlab.archlinux.org (devtools' rule: libsigc++ -> libsigcplusplus)."""
    name = re.sub(r"([a-zA-Z0-9]+)\+([a-zA-Z]+)", r"\1-\2", name).replace("+", "plus")
    name = re.sub(r"[_-]{2,}", "-", re.sub(r"[^a-zA-Z0-9_.-]", "-", name))
    return "unix-tree" if name == "tree" else name


def release_tags(state: str) -> dict:
    """{pkgbase: release tag} for core/extra/multilib, from Arch's packaging/state repo ("pkgbase version tag commit")."""
    tags = {}
    for repo in ("core-x86_64", "core-any", "extra-x86_64", "extra-any", "multilib-x86_64"):
        for f in glob.glob(os.path.join(state, repo, "*")):
            with open(f) as fh:
                parts = fh.read().split()
            if len(parts) >= 3:
                tags[parts[0]] = parts[2]
    return tags


def arch_fixes(version: str, commits: list[tuple[str, str]], srcinfo: str) -> dict:
    """
    {CVE: first Arch release with the fix} from the packaging history of
    `version`: `commits` are (message, changed file names), oldest first.
    A CVE counts when a fix/patch/backport commit message names it (reverts
    don't) or a patch file named after it is added; the release is the next
    "upgpkg: pkgver-pkgrel" commit. Commits for an older pkgver are ignored.
    CVEs only found in .SRCINFO's sources are dated to this release.
    """
    epoch_pkgver = version.rsplit("-", 1)[0]
    found, pending = {}, set()
    for msg, files in commits:
        m = re.match(r"\s*upgpkg: (\S+)-(\d+(?:\.\d+)?)\b", msg)
        if m and m.group(1) != epoch_pkgver and m.group(1).rpartition(":")[2] != epoch_pkgver.rpartition(":")[2]:
            found, pending = {}, set()  # an older pkgver: its fixes are judged by upstream versions
            continue
        if re.search(r"\b(fix|patch|backport|apply|cherry)", msg, re.I) and not re.search(r"\brevert", msg, re.I):
            pending |= {c.upper() for c in _CVE.findall(msg)}
        pending |= {c.upper() for c in _CVE.findall(files)}
        if m:
            for c in pending - found.keys():
                found[c] = f"{m.group(1)}-{m.group(2)}"
            pending = set()
    for c in {c.upper() for c in _CVE.findall(srcinfo)} | pending:
        found.setdefault(c, version)
    return found


def arch_packaging(feed: dict, workdir: str, previous: dict | None) -> dict:
    """
    {pkgbase: {CVE: first Arch release with the fix}} for pkgbases with open
    issues. Arch's packaging/state repo gives each package's release tag; a
    pkgbase keeps what was read at the same tag in the previous feed, and only
    released ones are fetched (that tag, shallow, small files only) for at
    most FETCH_MINUTES per run, most urgent first. When gitlab.archlinux.org refuses,
    the rest wait for the next run; their issues stay open meanwhile.
    """
    state = os.path.join(workdir, "state")
    subprocess.run(["rm", "-rf", state])
    if subprocess.run([*GIT, "clone", "--quiet", "--depth", "1", STATE_GIT, state], capture_output=True).returncode:
        print("warning: packaging/state unavailable; Arch patches kept from the previous feed only", file=sys.stderr)
    tags = release_tags(state)
    old = (previous or {}).get("pkgbases", {})
    found, todo = {}, []
    for base, b in feed["pkgbases"].items():
        open_ = [i for i in b["issues"] if i["status"] != "fixed"]
        prev = old.get(base, {})
        if prev.get("patched_tag") and prev["patched_tag"] == tags.get(base, prev["patched_tag"]):
            found[base] = (prev["patched_tag"], prev.get("patched", {}))
        elif open_ and base in tags:
            todo.append((not any(i["status"] in ("vulnerable", "unfixed") and not i.get("minor") for i in open_), base))
    deadline, refused = time.time() + FETCH_MINUTES * 60, False
    for _, base in sorted(todo):
        if time.time() > deadline or refused:
            break
        d, tag, ref = os.path.join(workdir, base), tags[base], f"refs/tags/{tags[base]}"
        subprocess.run(["git", "init", "--quiet", "--bare", d], capture_output=True)
        for wait in (0, 60):
            time.sleep(wait or 0.5)
            if not subprocess.run([*GIT, "-C", d, "fetch", "--quiet", "--depth", "50", "--filter=blob:limit=256k",
                                   ARCH_GIT.format(gitlab_path(base)), f"{ref}:{ref}"], capture_output=True).returncode:
                break
        else:
            refused = True
            continue
        git = lambda *a: subprocess.run(["git", "-C", d, *a], capture_output=True, text=True).stdout  # noqa: E731,B023
        log = git("log", "--reverse", "--format=%x01%B%x02", "--name-only", ref)
        commits = [tuple(c.split("\x02", 1)) for c in log.split("\x01")[1:]]
        found[base] = (tag, arch_fixes(feed["pkgbases"][base]["version"], commits, git("show", f"{ref}:.SRCINFO")))
    left = len([b for _, b in todo if b not in found])
    if left:
        print(f"note: {left} packaging repos left for the next run" + (" (gitlab.archlinux.org refused)" if refused else ""), file=sys.stderr)
    for base, (tag, fixes) in found.items():
        feed["pkgbases"][base]["patched_tag"], feed["pkgbases"][base]["patched"] = tag, fixes
    return {b: fixes for b, (_, fixes) in found.items() if fixes}


# --- the feed after the sources: Mozilla, Arch patches, history ---------------

def refine(feed: dict, mozilla: dict, patched: dict, previous: dict | None) -> None:
    """
    Apply Mozilla's verdicts and Arch's own patches ({pkgbase: {CVE: release}})
    to the feed, then record the first Arch build with each fix (`since`, an
    exact pkgver-pkgrel): the release that added Arch's patch, else carried
    over from the previous feed, else this build when the issue was open last time.
    """
    prev = {(b, i["id"]): i for b, e in (previous or {}).get("pkgbases", {}).items() for i in e["issues"]}
    for base, b in feed["pkgbases"].items():
        epoch = b["version"].rpartition(":")[0]
        k = key(b["version"]).rpartition(":")[2]
        issues = []
        for i in b["issues"]:
            if (base, i["id"]) in mozilla:
                v = cna_evaluate(k, mozilla[(base, i["id"])], newer_line_fixes=True)
                if v is None:
                    continue
                i = {"id": i["id"], **v, "via": "Mozilla", **({"minor": True} if i.get("minor") else {})}
                if epoch and "fixed" in i:
                    i["fixed"] = f"{epoch}:{i['fixed']}"
            if i["status"] != "fixed" and i["id"] in patched.get(base, {}):
                i = {"id": i["id"], "status": "fixed", "via": "Arch patch", "since": patched[base][i["id"]],
                     **({"minor": True} if i.get("minor") else {})}
            p = prev.get((base, i["id"]))
            if i["status"] == "fixed" and "since" not in i:
                if p and p.get("since"):
                    i["since"] = p["since"]
                elif p and p["status"] != "fixed":
                    i["since"] = b["version"]
            issues.append(i)
        b["issues"] = issues
    count = lambda st: sum(1 for b in feed["pkgbases"].values() for i in b["issues"] if i["status"] == st and not i.get("minor"))  # noqa: E731
    feed["stats"] = {"pkgbases": feed["stats"]["pkgbases"], "covered": len(feed["pkgbases"]),
                     **{st: count(st) for st in ("vulnerable", "unfixed", "uncertain")}}


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
                v = cna_evaluate(k.group(0), rules)
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
    ap.add_argument("--previous", default=os.environ.get("ARCH_CVE_FEED", FEED),
                    help="previously published feed (URL or file), for first-fixed builds; '' for none")
    ap.add_argument("--packaging", default="packaging", help="work dir for Arch's packaging/state and package repos")
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
    try:
        previous = load_feed(args.previous) if args.previous else None
        previous = previous if previous and previous.get("schema") == feed["schema"] else None
    except Exception as e:  # noqa: BLE001 - first run, or the site is down: start the history afresh
        print(f"previous feed unavailable ({e}); first-fixed builds start from this run", file=sys.stderr)
        previous = None
    refine(feed, mozilla_rules(feed), arch_packaging(feed, args.packaging, previous), previous)
    os.makedirs(os.path.join(args.out, "data"), exist_ok=True)
    with open(os.path.join(args.out, "data", "advisories.json"), "w") as f:
        json.dump(feed, f, separators=(",", ":"))
    with open(os.path.join(args.out, "all.json"), "w") as f:
        json.dump(arch_audit(feed), f, separators=(",", ":"))
    print(json.dumps(feed["stats"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
