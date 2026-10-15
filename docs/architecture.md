# Architecture

```
pacman -Sy + expac ─────────────┐
Debian security tracker JSON ───┤
Debian Sources (homepages) ─────┤
kernel CNA records (git clone) ─┼─► build.py ─► data/advisories.json ─► arch-cve-check (libalpm vercmp)
Mozilla CVE records (CVE API) ──┤               all.json             ─► arch-audit
Arch packaging (git clone) ─────┤                                    ─► the page (JS twin, tested against libalpm)
previous published feed ────────┘
```

Two Python files, standard library only: `build.py` (about 300 lines) and `arch_cve_check.py` (the
client, about 200 lines). The builder imports the client's version helpers, so the same code orders
versions on both sides. Every comparison goes through libalpm's `alpm_pkg_vercmp` via ctypes; nothing
re-implements pacman's ordering.

## Versions

Debian and Arch spell the same upstream release differently. `norm()` rewrites both into one spelling,
chosen so that pacman's ordering is right:

| Upstream | Debian | Arch | norm |
|---|---|---|---|
| patch releases | `1.9.17p2` | `1.9.17.p2` | `1.9.17.p2` (pacman sorts a glued `p2` *below* `1.9.17`) |
| pre-releases | `1.0~rc1` | `1.0rc1` | `1.0rc1` |
| dates | `20261009` | `2026_10_09` | `20261009` |
| tags | `2.1.13-stable` | `2.1.13` | `2.1.13` |

Debian versions additionally lose epoch, revision and repack markers (`+dfsg`, `+really`). Feed
thresholds are normalized upstream versions with Arch's epoch. The client normalizes the installed
`pkgver` the same way, keeping the epoch and dropping `pkgrel`.

## Matching a pkgbase to a Debian source

1. `aliases.json` (curated; checked by comparing homepages).
2. The same name. It is rejected when Debian's major version is more than twice Arch's (a different
   project with the same name).
3. `python-foo` → `python-foo` / `foo`, `perl-foo` → `libfoo-perl`, `foo` → `python-foo` / `foo2` /
   `libfoo-1.0`. These are accepted only when Debian's `Homepage` and Arch's `%URL%` name the same
   project. A versioned name must match Arch's release line (`ruby3.3` needs Arch 3.3.x).

## Verdicts (per pkgbase and CVE, Arch upstream version `a`)

In order:

1. **Exact version open:** a Debian release ships upstream `a` and marks it vulnerable.
   → `vulnerable` (when an upstream fix is known) or `unfixed`.
2. **Own-line fix:** a Debian upload that imports a new upstream release (`-1`, `-0.1`, `-1~bpo…`,
   `-0+debNuM`) fixed it on Arch's release line at or below `a`. → `fixed`.
3. **Debian unstable:**
   - not affected → dropped;
   - fixed by a new upstream release `u` → `fixed` if `a ≥ u`, else `vulnerable` (fix `u`);
   - fixed by a Debian patch on `u` → `u` is vulnerable, later releases are not (`upto: u`);
   - open → `unfixed` if `a` ≤ Debian's version, else `uncertain`;
   - undetermined → `uncertain`.

A fix on another release line never closes an issue (rule 2 is line-scoped). Rule 1 catches a Debian
version-scheme reset, e.g. libsixel's `1:1.8.7` while Debian trixie still has `1.10.5` open.

**Kernels** (`linux`, `-lts`, `-zen`, `-hardened`, `-rt`, `-rt-lts`) follow the kernel CNA's rules
for the upstream version (`6.18.55.rt6.arch1` → `6.18.55`):
- before `introduced` → dropped;
- a fix on its stable line (`6.18.30 ≤ 6.18.*`) → `fixed` / `vulnerable` with that threshold;
- else a mainline fix at or below it → `fixed`;
- else `vulnerable` (fixed only on newer lines) or `unfixed`.

## After the sources

`refine()` adjusts the verdicts in three passes.

- **Mozilla.** Debian ships ESR Thunderbird and lags on Firefox. For every Firefox or Thunderbird
  issue Debian leaves open, Mozilla's own CVE record decides. These records give the fix per line
  (`153.5 ≤ 153.*`) and in the release channel (`158 ≤ *`). Marked `"via": "Mozilla"`.
- **Arch's own patches.** Arch's `packaging/state` repo (one shallow clone per run) gives every
  package's current release tag. For pkgbases with open issues whose tag changed since the previous
  feed, only that tag of the package's repo is fetched: shallow, small files, one at a time, for at
  most `FETCH_MINUTES` (10) per run, most urgent first. The rest wait for the next run, as they do
  when gitlab.archlinux.org refuses; their issues stay open meanwhile.
  An issue counts as fixed in Arch when its CVE ID is in an added patch file's name, in `.SRCINFO`'s
  sources, or in a fix/patch/backport commit message (reverts don't count) for the current pkgver.
  The fix dates to the next `upgpkg: pkgver-pkgrel` release commit, which becomes `since`. What was
  read is stored in the feed with its tag (`patched_tag`, `patched`) and reused until the tag
  changes. Marked `"via": "Arch patch"`.
- **First fixed build.** The previous published feed is read back. When an issue was open there and is
  fixed now, this build's exact `pkgver-pkgrel` becomes `since`; Arch patches carry their own release. Later runs carry
  it over. `since` is compared with the installed version as pacman would, pkgrel included, so it is
  the most precise threshold. Issues fixed before the history started keep their upstream threshold.

## Feed (`data/advisories.json`, schema 2)

```json
{"schema": 2, "generated_at": 1792040000, "stats": {…},
 "packages": {"openssl": "openssl", …},
 "pkgbases": {"openssl": {"version": "3.6.5-1", "repo": "core", "source": "Debian openssl",
              "issues": [{"id": "CVE-…", "status": "fixed", "fixed": "3.6.5"},
                         {"id": "CVE-…", "status": "unfixed", "upto": "3.6.5", "minor": true}]}},
 "cves": {"CVE-…": "summary of open issues"}}
```

An installed version is affected by an issue when it is below `since` (an Arch build, pkgrel included),
else below `fixed`, else at or below `upto` (upstream versions), or when the issue has none of them. `status` says what the *repo* version is: `fixed` (an upgrade fixes older installs),
`vulnerable`, `unfixed`, `uncertain`. `minor` means Debian rates the issue unimportant; it is hidden
by default.

## Limits

- **Coverage.** About 1,680 of 12,400 pkgbases. The rest have no Debian counterpart we can match; the
  client lists them.
- **Arch patches** are seen only when the packaging names the CVE (patch file, source, or commit
  message). A patch taken without naming it stays invisible until the next upstream release.
- **Debian lags or differs.** Arch newer than Debian unstable and still "open" there gives `uncertain`
  (exit status 3). Firefox and Thunderbird use Mozilla's records for this.
- **First-upload-in-experimental** new upstream releases look like patches (thrift 0.23.0). This errs
  towards reporting.
- **Distro patches on an older release, for CVEs from before last year,** assume the next upstream
  release had the fix (`upto`). Debian's data has no dates to do better. Known case: glibc
  CVE-2023-4911 was patched by Debian in 2.37, so an install still on 2.38 is not flagged. For CVEs
  from this or last year, only Arch's current version counts as fixed.
- **Snapshot fixes:** Debian's `6.6+20251231` sorts after the `6.6` release, so a fix Debian took
  from a snapshot is reported against the release until Arch moves past it (ncurses).
- **Per-line sources** (`golang-1.27`, `python3.14`) only list the CVEs Debian considers relevant to
  that line. An install from an older line is checked against the current line's list.
- **Partial inputs fail the build:** a missing repo database, download or clone. The published feed then
  stays as it was, and both the client and the page flag a feed older than its normal refresh.
