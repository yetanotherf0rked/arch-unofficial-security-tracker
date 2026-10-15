#!/usr/bin/env python3
"""
Arch Linux repo security tracker — data refresh.

Pulls the current package list from Arch's official repository databases
(core / extra / multilib) and cross-references each package against OSV.dev
to find upstream CVEs. OSV.dev aggregates GHSA, NVD, Debian Security
Tracker, Ubuntu Security Notices and Alpine SecDB. Arch itself is not an
OSV ecosystem, so we query against Debian, Ubuntu and Alpine as proxies —
those distros key their records by *source* package, which maps to Arch's
pkgbase far better than to individual (split) binary package names.

Outputs:
  data/packages.json  — snapshot of fetched packages
  data/vulns.json     — pkgbase → CVEs mapping with metadata

Stdlib only. Designed to run inside GitHub Actions.
"""

from __future__ import annotations

import io
import json
import os
import re
import sys
import tarfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

MIRROR = os.environ.get(
    "ARCH_MIRROR",
    "https://geo.mirror.pkgbuild.com",
)
REPOS = ("core", "extra", "multilib")
ARCH = "x86_64"

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
PROXY_ECOSYSTEMS = ("Debian", "Ubuntu", "Alpine")

BATCH_SIZE = 1000
MAX_PAGES = 20  # per query; OSV paginates results for packages with huge histories
FETCH_WORKERS = 8
HTTP_TIMEOUT = 60
HTTP_RETRIES = 3

HERE = Path(__file__).parent
DATA = HERE / "data"
DATA.mkdir(exist_ok=True)


def http_get(url: str) -> bytes:
    """GET with retry on transient failures."""
    last: Exception | None = None
    for attempt in range(HTTP_RETRIES):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "arch-sec-tracker"})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                return r.read()
        except (urllib.error.URLError, TimeoutError) as e:
            last = e
            time.sleep(2 ** attempt)
    raise RuntimeError(f"GET failed after {HTTP_RETRIES} tries: {url}: {last}")


def http_post_json(url: str, payload: dict) -> dict:
    """POST JSON with retry."""
    body = json.dumps(payload).encode()
    last: Exception | None = None
    for attempt in range(HTTP_RETRIES):
        try:
            req = urllib.request.Request(
                url,
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "arch-sec-tracker",
                },
            )
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                return json.loads(r.read())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            last = e
            time.sleep(2 ** attempt)
    raise RuntimeError(f"POST failed after {HTTP_RETRIES} tries: {url}: {last}")


def fetch_repo_db(repo: str) -> list[dict[str, str]]:
    """Fetch and parse a repository .db.tar.gz, return [{name, base, version, repo}]."""
    url = f"{MIRROR}/{repo}/os/{ARCH}/{repo}.db.tar.gz"
    print(f"  fetching {url}", flush=True)
    blob = http_get(url)
    out: list[dict[str, str]] = []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for member in tf:
            if not member.isfile() or not member.name.endswith("/desc"):
                continue
            f = tf.extractfile(member)
            if f is None:
                continue
            desc = f.read().decode("utf-8", errors="replace")
            fields = parse_desc(desc)
            name = fields.get("NAME")
            version = fields.get("VERSION")
            if name and version:
                out.append({
                    "name": name,
                    "base": fields.get("BASE") or name,
                    "version": version,
                    "repo": repo,
                })
    return out


def parse_desc(text: str) -> dict[str, str]:
    """Parse an Arch repo `desc` file (key is `%KEY%`, value is next line(s))."""
    fields: dict[str, str] = {}
    key: str | None = None
    buf: list[str] = []
    for line in text.splitlines():
        if line.startswith("%") and line.endswith("%"):
            if key is not None:
                fields[key] = "\n".join(buf).strip()
            key = line.strip("%")
            buf = []
        elif line == "":
            if key is not None:
                fields[key] = "\n".join(buf).strip()
                key = None
                buf = []
        else:
            buf.append(line)
    if key is not None:
        fields[key] = "\n".join(buf).strip()
    return fields


def query_name(base: str) -> str:
    """Name to look up in proxy distros: multilib `lib32-foo` is built from `foo`."""
    return base[len("lib32-"):] if base.startswith("lib32-") else base


# ---------------------------------------------------------------------------
# Version handling
# ---------------------------------------------------------------------------

_ALPINE_REL_RE = re.compile(r"-r\d+$")
# Debian/Ubuntu revision or Arch pkgrel: "-1", "-1+deb12u1", "-1~deb11u1", "-0ubuntu0.2"
_REVISION_RE = re.compile(r"-[0-9][0-9A-Za-z.+~]*$")
# Debian "2.0+really1.9" means the tarball is actually 1.9
_REALLY_RE = re.compile(r"^.*[+~]really", re.I)
# Debian repack / backport markers glued onto the upstream part
_DISTRO_SUFFIX_RE = re.compile(
    r"[+~](?:dfsg|ds|repack|deb\d|ubuntu|build|nmu)[0-9A-Za-z.+~]*$", re.I
)


def upstream_version(ver: str) -> str:
    """
    Normalize a distro package version to an upstream-ish form:
      - strip leading epoch "N:"
      - strip trailing revision: Arch pkgrel, Debian/Ubuntu revision, Alpine "-rN"
      - strip Debian repack / backport markers (+dfsg, +ds, +repack, +debNuM, …)
      - resolve "+really" (take the real upstream version)
    """
    if ":" in ver:
        ver = ver.split(":", 1)[1]
    ver = _ALPINE_REL_RE.sub("", ver)
    ver = _REVISION_RE.sub("", ver)
    ver = _REALLY_RE.sub("", ver)
    ver = _DISTRO_SUFFIX_RE.sub("", ver)
    return ver


_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")
# Letter tokens that mark a pre-release when they trail a shorter version,
# e.g. Arch "1.0rc1" < "1.0". Single letters stay post-release ("1.1.1a" > "1.1.1").
_PRE_TOKENS = {"alpha", "beta", "pre", "rc"}


def _tokens(v: str) -> list[str]:
    return _TOKEN_RE.findall(v)


def _tokcmp(ta: list[str], tb: list[str]) -> int:
    for x, y in zip(ta, tb):
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            xi, yi = int(x), int(y)
            if xi != yi:
                return -1 if xi < yi else 1
        elif xn:
            return 1
        elif yn:
            return -1
        else:
            if x != y:
                return -1 if x < y else 1
    if len(ta) == len(tb):
        return 0
    longer_is_a = len(ta) > len(tb)
    nxt = (ta if longer_is_a else tb)[min(len(ta), len(tb))]
    longer_wins = not (nxt.isalpha() and nxt.lower() in _PRE_TOKENS)
    return 1 if longer_is_a == longer_wins else -1


def vercmp(a: str, b: str) -> int:
    """
    Simplified version compare, Debian-ish semantics. Returns -1 / 0 / 1.

    `~` is treated as pre-release (as in Debian): `1.0~rc1 < 1.0`.
    Within non-`~` parts, versions tokenize into digit/letter runs; digits
    compared numerically, letters lexically; digit tokens outrank letter
    tokens; a longer token sequence is greater unless the extra part starts
    with a pre-release marker (`1.0rc1 < 1.0`).
    """
    if a == b:
        return 0
    a_main, _, a_pre = a.partition("~")
    b_main, _, b_pre = b.partition("~")
    c = _tokcmp(_tokens(a_main), _tokens(b_main))
    if c != 0:
        return c
    # Same main: a release (no "~") outranks any pre-release ("~…").
    if a_pre and not b_pre:
        return -1
    if b_pre and not a_pre:
        return 1
    if not a_pre and not b_pre:
        return 0
    return _tokcmp(_tokens(a_pre), _tokens(b_pre))


def _branch(v: str) -> tuple[str, ...]:
    """Release branch: first two numeric components ("1.26.1" -> ("1", "26"))."""
    return tuple(t for t in _tokens(v) if t.isdigit())[:2]


def _major(v: str) -> int | None:
    toks = _tokens(v)
    return int(toks[0]) if toks and toks[0].isdigit() else None


# ---------------------------------------------------------------------------
# Matching an OSV record against an Arch version
# ---------------------------------------------------------------------------

def _ranges_for(record: dict, name: str) -> tuple[list[list[dict]], list[str]]:
    """Event lists of ECOSYSTEM/SEMVER ranges, and listed versions, for `name`."""
    ranges: list[list[dict]] = []
    versions: list[str] = []
    for aff in record.get("affected", []) or []:
        pkg = (aff.get("package") or {}).get("name", "")
        if pkg.lower() != name.lower():
            continue
        versions.extend(aff.get("versions", []) or [])
        for rng in aff.get("ranges", []) or []:
            if rng.get("type") in ("ECOSYSTEM", "SEMVER"):
                ranges.append(rng.get("events", []) or [])
    return ranges, versions


def evaluate(record: dict, name: str, version: str) -> tuple[str, list[str]]:
    """
    Decide whether Arch's upstream `version` of `name` is affected.

    Returns (status, fixed_versions) where status is one of:
      "affected"  — inside an affected range that has a known fix
      "unfixed"   — no fix exists anywhere in the record yet
      "fixed"     — Arch is at or past the fix
      "mismatch"  — would be affected, but Arch's version is far below anything
                    the record knows: likely a different project, same name
      "unknown"   — record has no usable ranges for this name
    """
    ranges, listed = _ranges_for(record, name)
    if not ranges:
        return "unknown", []

    intervals: list[tuple[str, str | None, str]] = []  # (lo, hi, kind)
    fixes: list[str] = []
    known: list[str] = [upstream_version(v) for v in listed]
    for events in ranges:
        lo: str | None = None
        for ev in events:
            if "introduced" in ev:
                lo = "0" if ev["introduced"] == "0" else upstream_version(ev["introduced"])
                if lo != "0":
                    known.append(lo)
            elif "fixed" in ev and lo is not None:
                hi = upstream_version(ev["fixed"])
                intervals.append((lo, hi, "fixed"))
                fixes.append(hi)
                lo = None
            elif "last_affected" in ev and lo is not None:
                hi = upstream_version(ev["last_affected"])
                intervals.append((lo, hi, "last"))
                known.append(hi)
                lo = None
        if lo is not None:
            intervals.append((lo, None, "open"))
    fixes = list(dict.fromkeys(f for f in fixes if f))
    known.extend(fixes)

    status = _status(version, intervals, fixes)

    # Name collision guard: Arch's version is far below every version the proxy
    # distro has ever recorded under this name (e.g. Arch's keystone assembler
    # 0.9 vs. Debian's OpenStack keystone 22+). Ordinary lag (chromium 154 vs.
    # a fix in 155) stays well inside the margin.
    if status in ("affected", "unfixed"):
        arch_major = _major(version)
        majors = [m for m in (_major(v) for v in known if v) if m is not None]
        if arch_major is not None and majors and arch_major * 2 + 1 < min(majors):
            return "mismatch", fixes
    return status, fixes


def _status(
    version: str, intervals: list[tuple[str, str | None, str]], fixes: list[str]
) -> str:
    # Branch-aware fix: Arch is at/after a fix released on its own branch.
    arch_branch = _branch(version)
    if any(_branch(f) == arch_branch and vercmp(version, f) >= 0 for f in fixes):
        return "fixed"

    def inside(lo: str, hi: str | None, kind: str) -> bool:
        if lo != "0" and vercmp(version, lo) < 0:
            return False
        if kind == "fixed":
            return vercmp(version, hi) < 0
        if kind == "last":
            return vercmp(version, hi) <= 0
        return True

    if any(inside(*iv) for iv in intervals if iv[2] != "open"):
        return "affected"
    # Open-ended ranges only mean "unfixed" when nobody has a fix yet; otherwise
    # they are just a distro release that hasn't picked up the fix.
    if not fixes and any(inside(*iv) for iv in intervals if iv[2] == "open"):
        return "unfixed"
    return "fixed"


# ---------------------------------------------------------------------------
# OSV.dev
# ---------------------------------------------------------------------------

def chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


def query_osv_batch(
    targets: list[tuple[str, str]],
) -> tuple[dict[tuple[str, str], set[str]], dict[str, str]]:
    """
    Query OSV.dev in batches. For each (name, upstream_version) target, send
    one query per proxy ecosystem, following `next_page_token` pagination.

    Returns a `(target_vulns, modified)` tuple:
      target_vulns: {(name, version): {vuln_id, …}}
      modified:     {vuln_id: last_modified_timestamp}
    """
    pending: list[tuple[int, dict]] = []
    for ti, (name, ver) in enumerate(targets):
        for eco in PROXY_ECOSYSTEMS:
            pending.append((ti, {"package": {"name": name, "ecosystem": eco}, "version": ver}))

    results: dict[tuple[str, str], set[str]] = {}
    modified: dict[str, str] = {}
    print(f"  querying OSV.dev: {len(pending)} queries in batches of {BATCH_SIZE}", flush=True)

    for page in range(MAX_PAGES):
        if not pending:
            break
        if page:
            print(f"  following pagination for {len(pending)} queries", flush=True)
        next_pending: list[tuple[int, dict]] = []
        for batch_i, batch in enumerate(chunks(pending, BATCH_SIZE)):
            resp = http_post_json(OSV_BATCH_URL, {"queries": [q for _, q in batch]})
            batch_results = resp.get("results", [])
            for (ti, q), r in zip(batch, batch_results):
                for v in r.get("vulns", []) or []:
                    vid = v.get("id")
                    if vid:
                        results.setdefault(targets[ti], set()).add(vid)
                        modified[vid] = v.get("modified", "")
                token = r.get("next_page_token")
                if token:
                    next_pending.append((ti, {**q, "page_token": token}))
            print(
                f"    batch {batch_i + 1}: {sum(1 for r in batch_results if r.get('vulns'))} hits",
                flush=True,
            )
            time.sleep(0.5)  # be polite
        pending = next_pending
    if pending:
        print(f"  WARNING: {len(pending)} queries still paginated after {MAX_PAGES} pages", file=sys.stderr)

    return results, modified


CACHE_PATH = DATA / "cve-cache.json"


def load_cache() -> dict[str, dict[str, Any]]:
    if CACHE_PATH.exists():
        try:
            return json.loads(CACHE_PATH.read_text())
        except json.JSONDecodeError:
            pass
    return {}


def fetch_vuln_records(
    ids_with_modified: list[tuple[str, str]],
) -> dict[str, dict[str, Any]]:
    """
    Fetch full OSV records for each (id, modified) pair, reusing cached
    records when their `modified` timestamp still matches. Only unknown or
    changed records hit the network, FETCH_WORKERS at a time.
    """
    cache = load_cache()
    out: dict[str, dict[str, Any]] = {}
    stale: list[str] = []
    for vid, mod in ids_with_modified:
        cached = cache.get(vid)
        if cached and cached.get("modified") == mod:
            out[vid] = cached
        else:
            stale.append(vid)
    print(
        f"  record cache: {len(out)} hits, {len(stale)} to fetch",
        flush=True,
    )

    def fetch(vid: str) -> tuple[str, dict[str, Any] | None]:
        try:
            return vid, json.loads(http_get(OSV_VULN_URL.format(id=vid)))
        except Exception as e:
            print(f"    skip {vid}: {e}", flush=True)
            return vid, None

    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        for i, (vid, rec) in enumerate(pool.map(fetch, stale)):
            if rec is not None:
                out[vid] = rec
                cache[vid] = rec
            if (i + 1) % 500 == 0:
                print(f"    {i + 1}/{len(stale)}", flush=True)
    CACHE_PATH.write_text(json.dumps(cache))
    return out


def summarize_record(record: dict[str, Any]) -> dict[str, Any]:
    """Pick the fields we show on the static page."""
    severity = ""
    for s in record.get("severity", []) or []:
        if s.get("type", "").startswith("CVSS"):
            severity = s.get("score", "")
            break
    vid = record.get("id", "")
    aliases = record.get("aliases", []) or []
    cve = next((a for a in aliases if a.startswith("CVE-")), "")
    if not cve:
        m = re.search(r"CVE-\d{4}-\d{4,7}", vid)
        if m:
            cve = m.group(0)
    return {
        "id": vid,
        "cve": cve,
        "summary": (record.get("summary") or record.get("details") or "").strip()[:300],
        "severity": severity,
        "aliases": aliases,
        "modified": record.get("modified", ""),
        "published": record.get("published", ""),
        "references": [
            r.get("url") for r in (record.get("references") or [])[:5] if r.get("url")
        ],
    }


def merge_by_cve(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse the same CVE reported by several distros into one entry."""
    merged: dict[str, dict[str, Any]] = {}
    for e in entries:
        key = e["cve"] or e["id"]
        if key not in merged:
            merged[key] = {**e, "sources": [e["id"]]}
            continue
        m = merged[key]
        m["sources"].append(e["id"])
        m["fixed_versions"] = list(dict.fromkeys(m["fixed_versions"] + e["fixed_versions"]))
        for field in ("summary", "severity"):
            if not m[field] and e[field]:
                m[field] = e[field]
    return sorted(merged.values(), key=lambda v: v["cve"] or v["id"], reverse=True)


def main() -> int:
    print("Fetching Arch repository databases...", flush=True)
    packages: list[dict[str, str]] = []
    for repo in REPOS:
        try:
            packages.extend(fetch_repo_db(repo))
        except Exception as e:
            print(f"  WARNING: could not fetch {repo}: {e}", file=sys.stderr)
    print(f"  total packages: {len(packages)}", flush=True)
    if not packages:
        print("No packages fetched; refusing to overwrite data.", file=sys.stderr)
        return 1

    (DATA / "packages.json").write_text(json.dumps({
        "generated_at": int(time.time()),
        "mirror": MIRROR,
        "count": len(packages),
        "packages": packages,
    }, indent=2))

    # One entry per (repo, pkgbase): split packages share a source and a CVE list.
    bases: dict[tuple[str, str], dict[str, Any]] = {}
    for p in packages:
        b = bases.setdefault((p["repo"], p["base"]), {
            "name": p["base"],
            "query": query_name(p["base"]),
            "version": p["version"],
            "upstream_version": upstream_version(p["version"]),
            "repo": p["repo"],
            "packages": [],
        })
        b["packages"].append(p["name"])
    print(f"  pkgbases: {len(bases)}", flush=True)

    print("Querying OSV.dev for candidate CVEs...", flush=True)
    targets = sorted({(b["query"], b["upstream_version"]) for b in bases.values()})
    candidate_vulns, modified = query_osv_batch(targets)

    unique_ids = sorted({vid for ids in candidate_vulns.values() for vid in ids})
    records = fetch_vuln_records([(vid, modified.get(vid, "")) for vid in unique_ids])

    stats = {"affected": 0, "unfixed": 0, "fixed": 0, "mismatch": 0, "unknown": 0}
    affected: list[dict[str, Any]] = []
    for b in bases.values():
        ids = candidate_vulns.get((b["query"], b["upstream_version"]))
        if not ids:
            continue
        found: list[dict[str, Any]] = []
        unfixed: list[dict[str, Any]] = []
        for vid in sorted(ids):
            rec = records.get(vid)
            if not rec:
                continue
            status, fixes = evaluate(rec, b["query"], b["upstream_version"])
            stats[status] += 1
            if status == "affected":
                found.append({**summarize_record(rec), "fixed_versions": fixes})
            elif status == "unfixed":
                unfixed.append({**summarize_record(rec), "fixed_versions": []})
        if found or unfixed:
            b.pop("query")
            b["vulns"] = merge_by_cve(found)
            b["unfixed"] = merge_by_cve(unfixed)
            affected.append(b)

    affected.sort(key=lambda x: (-len(x["vulns"]), -len(x["unfixed"]), x["name"]))
    print(f"  verification (package/record pairs): {stats}", flush=True)

    def unique(field: str) -> int:
        return len({v["cve"] or v["id"] for a in affected for v in a[field]})

    (DATA / "vulns.json").write_text(json.dumps({
        "generated_at": int(time.time()),
        "sources": {
            "packages": f"{MIRROR}/<repo>/os/{ARCH}/<repo>.db.tar.gz (repos: {', '.join(REPOS)})",
            "vulnerabilities": "OSV.dev — proxied via " + ", ".join(PROXY_ECOSYSTEMS),
        },
        "limitations": (
            "Arch is not an OSV ecosystem. CVEs are discovered via OSV queries against "
            "Debian / Ubuntu / Alpine using Arch pkgbase names, then verified locally "
            "against the affected ranges in each record. CVEs with no fix anywhere yet are "
            "listed separately as unfixed. False negatives possible when Arch names a "
            "package differently from those distros; false positives possible when Arch "
            "backports a patch without a version bump."
        ),
        "stats": stats,
        "affected_count": sum(1 for a in affected if a["vulns"]),
        "total_vulns": unique("vulns"),
        "unfixed_count": sum(1 for a in affected if a["unfixed"]),
        "total_unfixed": unique("unfixed"),
        "affected": affected,
    }, indent=2))

    print(
        f"Done. {sum(1 for a in affected if a['vulns'])} pkgbases with fixable CVEs, "
        f"{sum(1 for a in affected if a['unfixed'])} with unfixed-upstream CVEs."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
