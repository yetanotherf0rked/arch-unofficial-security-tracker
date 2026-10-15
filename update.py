#!/usr/bin/env python3
"""
Arch Linux repo security tracker — data refresh.

Pulls the current package list from Arch's official repository databases
(core / extra / multilib) and cross-references each package against OSV.dev
to find upstream CVEs. OSV.dev aggregates GHSA, NVD, Debian Security
Tracker, Ubuntu Security Notices and Alpine SecDB. Arch itself is not an
OSV ecosystem, so we query against Debian, Ubuntu and Alpine as proxies —
most Arch package names match upstream names used in those distros.

Outputs:
  data/packages.json  — snapshot of fetched packages
  data/vulns.json     — package → CVEs mapping with metadata

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
    """Fetch and parse a repository .db.tar.gz, return [{name, version, repo}]."""
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
                out.append({"name": name, "version": version, "repo": repo})
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


_PKGREL_RE = re.compile(r"-\d[\w.]*$")
_ALPINE_REL_RE = re.compile(r"-r\d+$")


def upstream_version(ver: str) -> str:
    """
    Normalize a distro package version to an upstream-ish form:
      - strip leading epoch "N:" (Debian, Arch, Alpine with epoch)
      - strip trailing Debian/Arch pkgrel "-N[.rest]" or Alpine "-rN"
    """
    if ":" in ver:
        ver = ver.split(":", 1)[1]
    ver = _ALPINE_REL_RE.sub("", ver)
    ver = _PKGREL_RE.sub("", ver)
    return ver


_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")


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
    if len(ta) != len(tb):
        return -1 if len(ta) < len(tb) else 1
    return 0


def vercmp(a: str, b: str) -> int:
    """
    Simplified version compare, Debian-ish semantics. Returns -1 / 0 / 1.

    `~` is treated as pre-release (as in Debian): `1.0~rc1 < 1.0`.
    Within non-`~` parts, versions tokenize into digit/letter runs; digits
    compared numerically, letters lexically; digit tokens outrank letter
    tokens; a longer token sequence is greater.
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


def extract_fixed_versions(record: dict, package_name: str) -> list[str]:
    """
    Return upstream-normalized fixed versions from an OSV record whose
    `affected[].package.name` matches package_name.
    """
    out: list[str] = []
    for aff in record.get("affected", []) or []:
        pkg = (aff.get("package") or {}).get("name", "")
        if pkg.lower() != package_name.lower():
            continue
        for rng in aff.get("ranges", []) or []:
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    out.append(upstream_version(ev["fixed"]))
    # dedupe, preserve order
    seen = set()
    uniq = []
    for v in out:
        if v and v not in seen:
            seen.add(v)
            uniq.append(v)
    return uniq


def chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


def query_osv_batch(
    packages: list[dict[str, str]],
) -> tuple[dict[str, list[str]], dict[str, str]]:
    """
    Query OSV.dev in batches. For each package, send one query per proxy
    ecosystem.

    Returns a `(package_vulns, modified)` tuple:
      package_vulns: {"<repo>/<name> <version>": [vuln_id, …]}
      modified:      {vuln_id: last_modified_timestamp}
    """
    queries: list[dict] = []
    index: list[str] = []  # package_key per query

    for p in packages:
        up = upstream_version(p["version"])
        key = f"{p['repo']}/{p['name']} {p['version']}"
        for eco in PROXY_ECOSYSTEMS:
            queries.append({
                "package": {"name": p["name"], "ecosystem": eco},
                "version": up,
            })
            index.append(key)

    results: dict[str, set[str]] = {}
    modified: dict[str, str] = {}
    total = len(queries)
    print(f"  querying OSV.dev: {total} queries in batches of {BATCH_SIZE}", flush=True)

    for batch_i, batch in enumerate(chunks(list(range(total)), BATCH_SIZE)):
        payload = {"queries": [queries[i] for i in batch]}
        resp = http_post_json(OSV_BATCH_URL, payload)
        batch_results = resp.get("results", [])
        for local_i, r in enumerate(batch_results):
            global_i = batch[local_i]
            key = index[global_i]
            for v in r.get("vulns", []):
                vid = v.get("id")
                if not vid:
                    continue
                results.setdefault(key, set()).add(vid)
                modified[vid] = v.get("modified", "")
        print(
            f"    batch {batch_i + 1}: {sum(1 for r in batch_results if r.get('vulns'))} hits",
            flush=True,
        )
        time.sleep(0.5)  # be polite

    return {k: sorted(v) for k, v in results.items()}, modified


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
    changed records hit the network.
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
    for i, vid in enumerate(stale):
        try:
            rec = json.loads(http_get(OSV_VULN_URL.format(id=vid)))
            out[vid] = rec
            cache[vid] = rec
        except Exception as e:
            print(f"    skip {vid}: {e}", flush=True)
        if (i + 1) % 200 == 0:
            print(f"    {i + 1}/{len(stale)}", flush=True)
        time.sleep(0.02)
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
        "summary": (record.get("summary") or "").strip()[:300],
        "severity": severity,
        "aliases": aliases,
        "modified": record.get("modified", ""),
        "published": record.get("published", ""),
        "references": [
            r.get("url") for r in (record.get("references") or [])[:5] if r.get("url")
        ],
    }


def main() -> int:
    print("Fetching Arch repository databases...", flush=True)
    packages: list[dict[str, str]] = []
    for repo in REPOS:
        try:
            packages.extend(fetch_repo_db(repo))
        except Exception as e:
            print(f"  WARNING: could not fetch {repo}: {e}", file=sys.stderr)
    print(f"  total packages: {len(packages)}", flush=True)

    (DATA / "packages.json").write_text(json.dumps({
        "generated_at": int(time.time()),
        "mirror": MIRROR,
        "count": len(packages),
        "packages": packages,
    }, indent=2))

    print("Querying OSV.dev for candidate CVEs...", flush=True)
    candidate_vulns, modified = query_osv_batch(packages)

    unique_ids = sorted({vid for ids in candidate_vulns.values() for vid in ids})
    records = fetch_vuln_records([(vid, modified.get(vid, "")) for vid in unique_ids])

    # Verify each candidate: Arch's upstream version must be < some fixed version
    # declared in the OSV record. Drop records with no usable fixed version — we
    # can't say they still apply to Arch.
    kept = 0
    dropped_fixed = 0
    dropped_unverifiable = 0

    affected: list[dict[str, Any]] = []
    for p in packages:
        key = f"{p['repo']}/{p['name']} {p['version']}"
        ids = candidate_vulns.get(key)
        if not ids:
            continue
        arch_upstream = upstream_version(p["version"])
        vulns: list[dict[str, Any]] = []
        for vid in ids:
            rec = records.get(vid)
            if not rec:
                continue
            fixes = extract_fixed_versions(rec, p["name"])
            if not fixes:
                dropped_unverifiable += 1
                continue
            # Keep if there exists some fixed version F such that arch < F.
            if any(vercmp(arch_upstream, f) < 0 for f in fixes):
                vulns.append({**summarize_record(rec), "fixed_versions": fixes})
                kept += 1
            else:
                dropped_fixed += 1
        if vulns:
            vulns.sort(key=lambda v: v.get("cve") or v["id"], reverse=True)
            affected.append({
                "name": p["name"],
                "version": p["version"],
                "upstream_version": arch_upstream,
                "repo": p["repo"],
                "vulns": vulns,
            })

    affected.sort(key=lambda x: (-len(x["vulns"]), x["name"]))

    stats = {
        "kept_pairs": kept,
        "dropped_already_fixed": dropped_fixed,
        "dropped_unverifiable": dropped_unverifiable,
    }
    print(f"  verification: {stats}", flush=True)

    (DATA / "vulns.json").write_text(json.dumps({
        "generated_at": int(time.time()),
        "sources": {
            "packages": f"{MIRROR}/<repo>/os/{ARCH}/<repo>.db.tar.gz (repos: {', '.join(REPOS)})",
            "vulnerabilities": "OSV.dev — proxied via " + ", ".join(PROXY_ECOSYSTEMS),
        },
        "limitations": (
            "Arch is not an OSV ecosystem. CVEs are discovered via OSV queries against "
            "Debian / Ubuntu / Alpine using Arch package names, then filtered locally "
            "by comparing Arch's upstream version to the fixed version in each OSV "
            "record. Records with no explicit fixed version are dropped (unverifiable). "
            "False negatives possible when Arch packages are renamed vs. upstream distros; "
            "false positives possible when Arch backports a patch without a version bump."
        ),
        "stats": stats,
        "affected_count": len(affected),
        "total_vulns": sum(len(a["vulns"]) for a in affected),
        "affected": affected,
    }, indent=2))

    print(f"Done. {len(affected)} affected packages, {kept} package/CVE pairs kept.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
