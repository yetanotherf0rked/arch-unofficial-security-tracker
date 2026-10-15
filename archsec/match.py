"""
Decide whether Arch's version of a package is affected by one issue, from
the OSV records (possibly several distros) that describe it.

A distro's "fixed" version is either a new upstream release that contains
the fix (Debian "1.2.4-1", Alpine "1.2.4-r0") or the distro's own patch on
an older release (Debian "1.2.3-3" or "1.2.3-1+deb13u1", Alpine
"1.2.3-r2"). Only the first kind says which upstream version is fixed; the
second says the upstream version it patched is still vulnerable. Treating
both alike (stripping the revision) used to report Arch's unpatched 1.2.3 as
fixed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .names import family, pypi_normalize
from .versions import branch, major, upstream_version, vercmp

# Debian revisions that import a new upstream release rather than patch one:
# "-1", "-0.1" (NMU), "-1~exp1", "-1~bpo12+1", "-1~deb12u1" (rebuild of
# unstable's -1), "-0+deb12u1" (new upstream straight into stable).
_DEB_UPSTREAM_REV = re.compile(r"^(?:0(?:\.\d+)?|1)(?:~.*)?$|^0\+deb\d+u\d+$")
_ALPINE_REL = re.compile(r"-r(\d+)$")

# Fixed version is an unreleased VCS snapshot: "1.4~hg15896" (before 1.4),
# "6.6+20251231" / "3.0.7+git20220909" (after 6.6 / 3.0.7), "2026.20260303.78225".
_SNAPSHOT_RE = re.compile(r"([~+.])(?:(?:hg|git|svn|bzr|cvs)\w*|(?:19|20)\d{6}(?!\d))", re.I)
# Arch builds from a VCS snapshot: "2.1.1791988261+2a8e017", "1.2.r45.gabc1234"
_ARCH_SNAPSHOT_RE = re.compile(r"\+[0-9a-f]{7,}$|\.r\d+\.g[0-9a-f]+$", re.I)
_DECIMAL_RE = re.compile(r"^\d+\.(\d+)$")


@dataclass
class Verdict:
    """
    status:
      vulnerable — Arch's version is affected; an upstream release fixes it
      unfixed    — affected, and no upstream release fixes it (distros may
                   carry their own patch: reason "patch-only" / "distro-patch*")
      uncertain  — the comparison can't be trusted (reason says why)
      fixed      — Arch's version has the fix (older versions may not)
      not_affected — Arch's version predates the issue
      mismatch   — the records likely describe another project with the same name
      unknown    — no usable range data
    """
    status: str
    reason: str = ""
    fixed_by: str | None = None    # upstream fix Arch is at or past
    next_fix: str | None = None    # upstream fix above Arch's version
    fixes: list[str] = field(default_factory=list)
    patches: list[str] = field(default_factory=list)
    patched_in: list[str] = field(default_factory=list)  # raw distro versions that patched it
    urgency: str | None = None


def relevant_entries(records: Iterable[dict[str, Any]], names: set[tuple[str, str]]) -> list[tuple[str, dict]]:
    """(family, affected-entry) pairs whose package is one of `names` ({(family, lowercase name)})."""
    out = []
    for rec in records:
        for aff in rec.get("affected", []) or []:
            pkg = aff.get("package") or {}
            fam = family(pkg.get("ecosystem", ""))
            name = pkg.get("name", "")
            key = pypi_normalize(name) if fam == "PyPI" else name.lower()
            if (fam, key) in names:
                out.append((fam, aff))
    return out


def fix_kind(raw: str, fam: str, listed: list[str]) -> str:
    """
    "upstream" if `raw` is a release containing the fix, "patch" if it's a
    distro patch. `listed` are the distro versions the record marks affected.
    """
    up = upstream_version(raw)
    # The distro shipped an affected build of this same upstream version.
    # Backport/experimental builds of the fixing upload itself ("2.7.8-1~bpo13+1"
    # sorts below "2.7.8-1") are only listed because of how Debian orders versions.
    if fam != "Linux" and any(upstream_version(v) == up for v in listed if not v.startswith(raw + "~")):
        return "patch"
    if fam == "Debian":
        ver = raw.split(":", 1)[-1]
        if "-" not in ver:
            return "upstream"  # native package
        return "upstream" if _DEB_UPSTREAM_REV.match(ver.rsplit("-", 1)[1]) else "patch"
    if fam == "Alpine":
        m = _ALPINE_REL.search(raw)
        return "patch" if m and m.group(1) != "0" else "upstream"
    return "upstream"


def _release_rank(ecosystem: str) -> tuple[int, ...]:
    """"Debian:13" -> (13,), "Alpine:v3.24" -> (3, 24), "PyPI" -> (0,)."""
    return tuple(int(x) for x in re.findall(r"\d+", ecosystem.split(":", 1)[-1])) or (0,)


def debian_urgency(entries: list[tuple[str, dict]]) -> str | None:
    """Urgency the newest Debian release gives the issue ("unimportant", "low", …)."""
    deb = [a for fam, a in entries if fam == "Debian"]
    if not deb:
        return None
    newest = max(deb, key=lambda a: _release_rank((a.get("package") or {}).get("ecosystem", "")))
    u = (newest.get("ecosystem_specific") or {}).get("urgency")
    return u if u in ("unimportant", "low", "medium", "high") else None


def evaluate(
    entries: list[tuple[str, dict]],
    version: str,
    builddate: int = 0,
    published: int = 0,
) -> Verdict:
    """
    `version` is Arch's upstream version (`upstream_version` of pkgver);
    `builddate` / `published` (Unix time) tell whether Arch's build predates
    the issue, which decides how to read a distro patch on the same version.
    """
    urgency = debian_urgency(entries)
    intervals: list[tuple[str, str | None, str]] = []  # (lo, hi, kind)
    fixes: list[str] = []
    patches: list[str] = []
    patched_in: list[str] = []
    known: list[str] = []
    assessed: list[str] = []  # versions the newest releases list as still affected
    # Only the newest release of each distro says whether a fix is still
    # missing; old releases stay open forever once they reach end of life.
    newest: dict[str, tuple[int, ...]] = {}
    for fam, aff in entries:
        rank = _release_rank((aff.get("package") or {}).get("ecosystem", ""))
        newest[fam] = max(newest.get(fam, rank), rank)
    for fam, aff in entries:
        is_newest = _release_rank((aff.get("package") or {}).get("ecosystem", "")) == newest[fam]
        listed = aff.get("versions", []) or []
        known.extend(upstream_version(v) for v in listed)
        for rng in aff.get("ranges", []) or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            lo: str | None = None
            for ev in rng.get("events", []) or []:
                if "introduced" in ev:
                    lo = "0" if ev["introduced"] == "0" else upstream_version(ev["introduced"])
                    if lo != "0":
                        known.append(lo)
                elif "fixed" in ev and lo is not None:
                    hi = upstream_version(ev["fixed"])
                    if fix_kind(ev["fixed"], fam, listed) == "upstream":
                        intervals.append((lo, hi, "fixed"))
                        fixes.append(hi)
                    else:
                        intervals.append((lo, hi, "patch"))
                        patches.append(hi)
                        patched_in.append(f"{(aff.get('package') or {}).get('ecosystem', fam)} {ev['fixed']}")
                    lo = None
                elif "last_affected" in ev and lo is not None:
                    hi = upstream_version(ev["last_affected"])
                    intervals.append((lo, hi, "last"))
                    known.append(hi)
                    lo = None
            if lo is not None and is_newest:
                intervals.append((lo, None, "open"))
                assessed.extend(upstream_version(v) for v in listed)
    if not intervals:
        return Verdict("unknown", urgency=urgency)
    # Snapshot schemes like "r12985.5236ecb04" can't be compared with release numbers.
    if not version[:1].isdigit():
        return Verdict("unknown", urgency=urgency)

    fixes = list(dict.fromkeys(f for f in fixes if f))
    patches = list(dict.fromkeys(p for p in patches if p))
    known.extend(fixes + patches)
    v = _status(version, intervals, fixes, patches, builddate, published, assessed)
    v.fixes, v.patches, v.urgency = fixes, patches, urgency
    v.patched_in = list(dict.fromkeys(patched_in))

    # Name collision guard: Arch's version is far below every version the proxy
    # distro has ever recorded under this name (e.g. Arch's keystone assembler
    # 0.9 vs. Debian's OpenStack keystone 22+). Ordinary lag (chromium 154 vs.
    # a fix in 155) stays well inside the margin.
    if v.status in ("vulnerable", "uncertain", "unfixed"):
        arch_major = major(version)
        majors = [m for m in (major(k) for k in known if k) if m is not None]
        if arch_major is not None and majors and arch_major * 2 + 1 < min(majors):
            return Verdict("mismatch", fixes=fixes, patches=patches, urgency=urgency)
    return v


def _inside(version: str, lo: str, hi: str | None, kind: str) -> bool:
    if lo != "0" and vercmp(version, lo) < 0:
        return False
    if kind in ("fixed", "patch"):
        return vercmp(version, hi) < 0
    if kind == "last":
        return vercmp(version, hi) <= 0
    return True


def _pick_next_fix(version: str, fixes: list[str]) -> str | None:
    """The smallest upstream fix above Arch's version, preferring Arch's release line."""
    above = [f for f in fixes if vercmp(version, f) < 0]
    if not above:
        return None
    own = [f for f in above if branch(f) == branch(version)]
    return _vmin(own or above)


def _vmin(vs: list[str]) -> str:
    best = vs[0]
    for x in vs[1:]:
        if vercmp(x, best) < 0:
            best = x
    return best


def _vmax(vs: list[str]) -> str:
    best = vs[0]
    for x in vs[1:]:
        if vercmp(x, best) > 0:
            best = x
    return best


def _status(
    version: str,
    intervals: list[tuple[str, str | None, str]],
    fixes: list[str],
    patches: list[str],
    builddate: int,
    published: int,
    assessed: list[str],
) -> Verdict:
    # Branch-aware fix: Arch is at/after an upstream fix released on its own branch.
    arch_branch = branch(version)
    own = [f for f in fixes if branch(f) == arch_branch and vercmp(version, f) >= 0]
    if own:
        return Verdict("fixed", fixed_by=_vmin(own))

    hits = [iv for iv in intervals if iv[2] != "open" and _inside(version, *iv)]
    if hits:
        reason = _uncertain(version, hits, fixes)
        nxt = _pick_next_fix(version, fixes)
        if reason:
            return Verdict("uncertain", reason, next_fix=nxt)
        if nxt:
            return Verdict("vulnerable", "below-fix", next_fix=nxt)
        # No upstream release fixes it; distros may carry their own patch.
        return Verdict("unfixed", "patch-only" if any(k == "patch" for _, _, k in hits) else "no-fix")

    # A distro had to patch the very upstream version Arch ships. Arch may
    # carry the same patch if it rebuilt since the issue was published; NVD
    # and MITRE call such builds affected about 15 times as often as not.
    if any(vercmp(version, p) == 0 for p in patches):
        nxt = _pick_next_fix(version, fixes)
        rebuilt = not (builddate and published and builddate < published)
        return Verdict("vulnerable" if nxt else "unfixed",
                       "distro-patch-rebuilt" if rebuilt else "distro-patch", next_fix=nxt)

    # An open range in a distro's newest release means "not fixed yet" unless
    # some upstream release is known to fix it.
    opens = [iv for iv in intervals if iv[2] == "open" and _inside(version, *iv)]
    if opens and not fixes:
        # Arch is newer than every version the distro has looked at: "still
        # open" there says nothing about Arch's release (distros lag behind
        # upstream, e.g. Debian's ESR Thunderbird vs Arch's current one).
        if assessed and all(vercmp(version, a) > 0 for a in assessed):
            return Verdict("uncertain", "newer-than-assessed")
        return Verdict("unfixed", "patch-only" if patches else "no-fix")

    if all(lo != "0" and vercmp(version, lo) < 0 for lo, _, _ in intervals):
        return Verdict("not_affected")
    below = [f for f in fixes if vercmp(version, f) >= 0]
    return Verdict("fixed", fixed_by=_vmax(below) if below else None)


def _uncertain(version: str, hits: list[tuple[str, str | None, str]], fixes: list[str]) -> str:
    """
    A reason when Arch's version falls in an affected range but the
    comparison is unreliable, else "":
      - Arch is already past a fix on another release line and the range
        it falls in has no lower bound, so it sits between lines and we
        can't tell whether its own line got the fix;
      - Arch builds from a VCS snapshot, which may well include the fix;
      - every fix that puts Arch in range is a distro VCS snapshot whose
        position relative to Arch's release is unknown, or a two-part
        "decimal" version whose digits don't line up ("2.88" vs "2.720").
    """
    # A range with its own lower bound ("introduced 6.19.0") is scoped to a
    # release line and settles it; only unbounded ranges leave Arch between lines.
    if all(lo == "0" for lo, _, _ in hits) and any(vercmp(version, f) >= 0 for f in fixes):
        return "between-branches"
    if _ARCH_SNAPSHOT_RE.search(version):
        return "arch-snapshot"

    why = ""

    def decisive(hi: str | None) -> bool:
        nonlocal why
        if hi is None:
            return True
        m = _SNAPSHOT_RE.search(hi)
        if m:
            # Only a snapshot taken after a release newer than Arch's is conclusive.
            if m.group(1) != "~" and vercmp(version, hi[: m.start()]) < 0:
                return True
            why = why or "fix-snapshot"
            return False
        a, b = _DECIMAL_RE.match(version), _DECIMAL_RE.match(hi)
        if a and b and len(a.group(1)) != len(b.group(1)):
            why = why or "version-scheme"
            return False
        return True

    return "" if any([decisive(hi) for _, hi, _ in hits]) else why
