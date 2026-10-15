"""Matching OSV records against Arch versions (archsec.match)."""

import unittest

from archsec.match import evaluate, fix_kind, relevant_entries


def rec(*affected, rid="DEBIAN-CVE-2026-0001"):
    return {"id": rid, "affected": list(affected)}


def aff(eco, name, *events, versions=(), urgency=None):
    a = {
        "package": {"ecosystem": eco, "name": name},
        "ranges": [{"type": "ECOSYSTEM", "events": list(events)}],
        "versions": list(versions),
    }
    if urgency:
        a["ecosystem_specific"] = {"urgency": urgency}
    return a


def intro(v="0"):
    return {"introduced": v}


def fixed(v):
    return {"fixed": v}


def run(records, version, name="foo", fam=None, **kw):
    names = {(f, name) for f in (fam or ("Debian", "Alpine", "PyPI"))}
    return evaluate(relevant_entries(records, names), version, **kw)


class FixKind(unittest.TestCase):
    def test_debian_revisions(self):
        self.assertEqual(fix_kind("1.2.4-1", "Debian", []), "upstream")
        self.assertEqual(fix_kind("1.2.4-0.1", "Debian", []), "upstream")
        self.assertEqual(fix_kind("1.2.4-1~deb13u1", "Debian", []), "upstream")
        self.assertEqual(fix_kind("1.2.4-0+deb13u1", "Debian", []), "upstream")
        self.assertEqual(fix_kind("1.2.4", "Debian", []), "upstream")  # native
        self.assertEqual(fix_kind("1.2.3-3", "Debian", []), "patch")
        self.assertEqual(fix_kind("1.2.3-1+deb13u1", "Debian", []), "patch")
        self.assertEqual(fix_kind("1.2.3-1.1", "Debian", []), "patch")

    def test_affected_build_of_same_version_means_patch(self):
        self.assertEqual(fix_kind("1.2.4-1", "Debian", ["1.2.4-0.1"]), "patch")

    def test_backport_of_fixing_upload_is_ignored(self):
        # "2.7.8-1~bpo13+1" sorts below "2.7.8-1", so it lands in the affected list.
        self.assertEqual(fix_kind("2.7.8-1", "Debian", ["2.7.7-1", "2.7.8-1~bpo13+1"]), "upstream")

    def test_alpine(self):
        self.assertEqual(fix_kind("1.2.4-r0", "Alpine", []), "upstream")
        self.assertEqual(fix_kind("1.2.3-r2", "Alpine", []), "patch")


class Evaluate(unittest.TestCase):
    def test_below_fix_is_vulnerable(self):
        v = run([rec(aff("Debian:14", "foo", intro(), fixed("155.0.8059.39-1")))], "154.0.8037.97")
        self.assertEqual((v.status, v.reason, v.next_fix), ("vulnerable", "below-fix", "155.0.8059.39"))

    def test_at_fix_is_fixed(self):
        v = run([rec(aff("Debian:14", "foo", intro(), fixed("1.2.4-1")))], "1.2.4")
        self.assertEqual((v.status, v.fixed_by), ("fixed", "1.2.4"))

    def test_stable_backport_does_not_hide_upstream_fix(self):
        # Debian 13 patched 1.2.3; upstream fixed it in 1.2.9 (testing). Arch 1.2.5
        # is on the same 1.2 line as the patched version but still vulnerable.
        r = rec(
            aff("Debian:13", "foo", intro(), fixed("1.2.3-1+deb13u1")),
            aff("Debian:14", "foo", intro(), fixed("1.2.9-1")),
        )
        v = run([r], "1.2.5")
        self.assertEqual((v.status, v.next_fix), ("vulnerable", "1.2.9"))

    def test_distro_patch_on_same_version(self):
        r = rec(aff("Debian:14", "foo", intro(), fixed("0.9.15+dfsg-3"), versions=["0.9.15+dfsg-1", "0.9.15+dfsg-2"]))
        before = run([r], "0.9.15", builddate=1000, published=2000)
        self.assertEqual((before.status, before.reason), ("unfixed", "distro-patch"))
        self.assertTrue(before.patched_in)
        after = run([r], "0.9.15", builddate=3000, published=2000)
        self.assertEqual((after.status, after.reason), ("uncertain", "distro-patch-rebuilt"))

    def test_only_patches_below_arch(self):
        r = rec(aff("Debian:14", "foo", intro(), fixed("1.38.0-3"), versions=["1.38.0-1"]))
        v = run([r], "1.36.1")
        self.assertEqual((v.status, v.reason), ("unfixed", "patch-only"))

    def test_unfixed(self):
        r = rec(aff("Debian:14", "foo", intro(), versions=["2.0-1", "2.1-1"]))
        self.assertEqual(run([r], "2.1").status, "unfixed")

    def test_newer_than_assessed(self):
        r = rec(aff("Debian:14", "foo", intro(), versions=["140.3.0-1", "140.4.0-1"]))
        v = run([r], "157.0.1")
        self.assertEqual((v.status, v.reason), ("uncertain", "newer-than-assessed"))

    def test_open_range_in_old_release_only(self):
        # Debian 11 never got a fix; the newest release did.
        r = rec(
            aff("Debian:11", "foo", intro(), versions=["1.0-1"]),
            aff("Debian:14", "foo", intro(), fixed("1.1-1")),
        )
        self.assertEqual(run([r], "1.2").status, "fixed")

    def test_other_distro_fix_counts(self):
        r1 = rec(aff("Debian:14", "foo", intro(), urgency="unimportant"))
        r2 = rec(aff("Alpine:v3.24", "foo", intro(), fixed("2.37.4-r0")), rid="ALPINE-CVE-2026-0001")
        v = run([r1, r2], "2.41")
        self.assertEqual((v.status, v.fixed_by, v.urgency), ("fixed", "2.37.4", "unimportant"))

    def test_name_collision(self):
        # Arch's keystone assembler 0.9 vs Debian's OpenStack keystone 22+.
        r = rec(aff("Debian:14", "foo", intro(), fixed("2:22.0.1-1"), versions=["2:22.0.0-1"]))
        self.assertEqual(run([r], "0.9.2").status, "mismatch")

    def test_decimal_versions_are_uncertain(self):
        r = rec(aff("Debian:14", "foo", intro(), fixed("2.720-1")))
        v = run([r], "2.88")
        self.assertEqual((v.status, v.reason), ("uncertain", "version-scheme"))

    def test_snapshot_fix_is_uncertain(self):
        r = rec(aff("Debian:14", "foo", intro(), fixed("1.4~hg15896-1")))
        v = run([r], "1.3")
        self.assertEqual((v.status, v.reason), ("uncertain", "fix-snapshot"))

    def test_between_branches(self):
        r = rec(
            aff("Debian:13", "foo", intro(), fixed("1.26.3-1~deb13u1")),
            aff("Debian:14", "foo", intro(), fixed("1.28.1-1")),
        )
        v = run([r], "1.27.0")
        self.assertEqual((v.status, v.reason), ("uncertain", "between-branches"))

    def test_fix_on_own_branch(self):
        r = rec(
            aff("Debian:13", "foo", intro(), fixed("1.27.2-1~deb13u1")),
            aff("Debian:14", "foo", intro(), fixed("1.28.1-1")),
        )
        v = run([r], "1.27.4")
        self.assertEqual((v.status, v.fixed_by), ("fixed", "1.27.2"))

    def test_introduced_later(self):
        r = rec(aff("PyPI", "foo", intro("2.0"), fixed("2.3")))
        self.assertEqual(run([r], "1.5").status, "not_affected")

    def test_pypi_last_affected(self):
        r = {"id": "GHSA-xxxx", "affected": [{
            "package": {"ecosystem": "PyPI", "name": "Foo_Bar"},
            "ranges": [{"type": "ECOSYSTEM", "events": [intro("1.0"), {"last_affected": "1.4"}]}],
        }]}
        v = run([r], "1.4", name="foo-bar", fam=("PyPI",))
        self.assertEqual((v.status, v.reason), ("unfixed", "no-fix"))

    def test_kernel_branches(self):
        r = {"id": "CVE-2026-0002", "affected": [{
            "package": {"ecosystem": "Linux", "name": "Kernel"},
            "ranges": [{"type": "ECOSYSTEM", "events": [intro("6.13.0"), fixed("6.18.40")]},
                       {"type": "ECOSYSTEM", "events": [intro("6.19.0"), fixed("7.2.6")]}],
        }]}
        lts = run([r], "6.18.56", name="kernel", fam=("Linux",))
        self.assertEqual((lts.status, lts.fixed_by), ("fixed", "6.18.40"))
        self.assertEqual(run([r], "6.18.39", name="kernel", fam=("Linux",)).next_fix, "6.18.40")
        self.assertEqual(run([r], "7.2.5.arch1", name="kernel", fam=("Linux",)).status, "vulnerable")
        self.assertEqual(run([r], "7.2.9.arch1", name="kernel", fam=("Linux",)).status, "fixed")

    def test_arch_snapshot_version(self):
        self.assertEqual(run([rec(aff("Debian:14", "foo", intro(), fixed("2.0-1")))], "r12985.5236ecb04").status, "unknown")


if __name__ == "__main__":
    unittest.main()
