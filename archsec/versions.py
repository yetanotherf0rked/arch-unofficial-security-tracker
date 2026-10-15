"""
Upstream-version handling for matching distro records against Arch.

Debian, Alpine and PyPI write versions differently from Arch. Everything is
first reduced to an "upstream" form (`upstream_version`) and compared with a
Debian-ish ordering (`vercmp`). Comparing an Arch version with a version from
the feed on a user's machine uses pacman's own ordering instead
(`archsec.check.vercmp`).
"""

from __future__ import annotations

import re
from functools import lru_cache

_ALPINE_REL_RE = re.compile(r"-r\d+$")
# Debian/Ubuntu revision or Arch pkgrel: "-1", "-1+deb12u1", "-1~deb11u1", "-0ubuntu0.2"
_REVISION_RE = re.compile(r"-[0-9][0-9A-Za-z.+~]*$")
# Debian "2.0+really1.9" means the tarball is actually 1.9
_REALLY_RE = re.compile(r"^.*[+~]really", re.I)
# Debian repack / backport markers glued onto the upstream part
_DISTRO_SUFFIX_RE = re.compile(
    r"[+~](?:dfsg|ds|repack|deb\d|ubuntu|build|nmu|real)[0-9A-Za-z.+~]*$", re.I
)
# Arch writes pre-releases inline ("2.11.0beta2"), Debian with "~" ("2.11.0~beta2")
_INLINE_PRE_RE = re.compile(r"(?<=\d)[._-]?(alpha|beta|pre|rc|dev)(?=\d|$)", re.I)
# Date versions: Arch "2026_10_09" vs Debian "20261009"
_DATE_RE = re.compile(r"^((?:19|20)\d{2})([._-])(\d{2})[._-](\d{2})(?!\d)")


@lru_cache(maxsize=1 << 16)
def upstream_version(ver: str) -> str:
    """
    Normalize a distro package version to an upstream-ish form:
      - strip leading epoch "N:"
      - strip trailing revision: Arch pkgrel, Debian/Ubuntu revision, Alpine "-rN"
      - strip Debian repack / backport markers (+dfsg, +ds, +repack, +debNuM, …)
      - resolve "+really" (take the real upstream version)
      - write inline pre-releases with "~" ("1.0rc1" -> "1.0~rc1")
    """
    if ":" in ver:
        ver = ver.split(":", 1)[1]
    ver = _ALPINE_REL_RE.sub("", ver)
    ver = _REVISION_RE.sub("", ver)
    ver = _REALLY_RE.sub("", ver)
    ver = _DISTRO_SUFFIX_RE.sub("", ver)
    if "~" not in ver:
        ver = _INLINE_PRE_RE.sub(r"~\1", ver, count=1)
    return _DATE_RE.sub(r"\1\3\4", ver)


_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")
# Letter tokens that mark a pre-release when they trail a shorter version,
# e.g. Arch "1.0rc1" < "1.0". Single letters stay post-release ("1.1.1a" > "1.1.1").
_PRE_TOKENS = {"alpha", "beta", "pre", "rc", "dev"}


def tokens(v: str) -> list[str]:
    return _TOKEN_RE.findall(v.lower())


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
    c = _tokcmp(tokens(a_main), tokens(b_main))
    if c != 0:
        return c
    # Same main: a release (no "~") outranks any pre-release ("~…").
    if a_pre and not b_pre:
        return -1
    if b_pre and not a_pre:
        return 1
    if not a_pre and not b_pre:
        return 0
    return _tokcmp(tokens(a_pre), tokens(b_pre))


def branch(v: str) -> tuple[str, ...]:
    """Release branch: first two numeric components ("1.26.1" -> ("1", "26"))."""
    return tuple(t for t in tokens(v) if t.isdigit())[:2]


def major(v: str) -> int | None:
    toks = tokens(v)
    return int(toks[0]) if toks and toks[0].isdigit() else None


# ---------------------------------------------------------------------------
# Arch version strings
# ---------------------------------------------------------------------------

def split_arch(version: str) -> tuple[str, str, str]:
    """"1:2.3-4" -> ("1", "2.3", "4"); missing epoch is "", missing pkgrel is ""."""
    epoch, _, rest = version.rpartition(":") if ":" in version else ("", "", version)
    pkgver, _, pkgrel = rest.rpartition("-") if "-" in rest else (rest, "", "")
    return epoch, pkgver, pkgrel


def arch_form(upstream: str, arch_version: str) -> str:
    """
    Write an upstream version the way Arch would version that release, so
    pacman's ordering can compare it with installed packages: Arch's epoch
    is carried over, "~rc1" becomes inline "rc1", and a date is split with
    Arch's separator ("20261009" -> "2026_10_09"). No pkgrel: pacman then
    compares epoch and pkgver only, so every pkgrel of that release counts.
    """
    epoch, pkgver, _ = split_arch(arch_version)
    v = upstream.replace("~", "")
    m = _DATE_RE.match(pkgver)
    if m:
        sep = m.group(2)
        v = re.sub(r"^((?:19|20)\d{2})(\d{2})(\d{2})(?!\d)", rf"\1{sep}\2{sep}\3", v)
    return f"{epoch}:{v}" if epoch else v
