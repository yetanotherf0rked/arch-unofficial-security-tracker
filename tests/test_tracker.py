"""python -m unittest — rules of build.py and arch_cve_check.py (needs libalpm, i.e. Arch)."""

import subprocess
import unittest

import arch_cve_check as c
import build as b


def rec(**releases):
    """A Debian tracker record: rec(sid=("resolved", "1.2.4-1", "1.2.4-1"), trixie=("open", None, "1.2.3-1"))."""
    out = {}
    for name, (status, fixed, repo) in releases.items():
        out[name] = {"status": status, "repositories": {name: repo}, "urgency": "not yet assigned"}
        if fixed:
            out[name]["fixed_version"] = fixed
    return {"releases": out}


class Versions(unittest.TestCase):
    def test_vercmp_is_pacmans(self):
        for a, bb in [("1.9.13.p2-1", "1.9.13p3"), ("7.2.9.arch1-1", "7.2.10"), ("1:1.0", "2.0"), ("1.0rc1", "1.0")]:
            want = int(subprocess.run(["vercmp", a, bb], capture_output=True, text=True).stdout)
            self.assertEqual(c.vercmp(a, bb), want, (a, bb))

    def test_norm(self):
        for raw, want in [("1.9.17p2", "1.9.17.p2"), ("1.9.17.p2", "1.9.17.p2"), ("10.6p1", "10.6.p1"),
                          ("2026_10_09", "20261009"), ("2.1.13-stable", "2.1.13"), ("1.0~rc1", "1.0rc1"),
                          ("7.3-rc1", "7.3rc1"), ("2.11.0beta2", "2.11.0beta2"), ("8.3_p1", "8.3.p1")]:
            self.assertEqual(c.norm(raw), want, raw)

    def test_key_and_affects(self):
        self.assertEqual(c.key("1:2.3_p1-4"), "1:2.3.p1")
        self.assertTrue(c.affects("1.9.5.p1-1", {"fixed": "1.9.5.p2"}))      # Baron Samedit
        self.assertTrue(c.affects("1.9.13.p2-1", {"fixed": "1.9.13.p3"}))
        self.assertFalse(c.affects("1.9.13.p3-1", {"fixed": "1.9.13.p3"}))
        self.assertTrue(c.affects("1.2.3-9", {"upto": "1.2.3"}))             # distro patch on 1.2.3
        self.assertFalse(c.affects("1.2.4-1", {"upto": "1.2.3"}))
        self.assertTrue(c.affects("0.1-1", {}))                             # no fix known

    def test_debian_versions(self):
        self.assertEqual(b.deb_upstream("1:1.3.dfsg+really1.3.2-3"), "1.3.2")
        self.assertEqual(b.deb_upstream("2.14.3+dfsg-3"), "2.14.3")
        self.assertEqual(b.deb_upstream("1:1.8.7-r2-1"), "1.8.7.r2")
        self.assertEqual(b.deb_upstream("260~rc3-1"), "260rc3")
        for v, new in [("1.2.4-1", True), ("1.2.4-0.1", True), ("2.7.8-1~bpo13+1", True), ("1.2-0+deb13u1", True),
                       ("20260101", True), ("1.2.3-3", False), ("1.2.3-1+deb13u1", False), ("1.2.3-1.1", False)]:
            self.assertEqual(b.new_upstream(v), new, v)


class Debian(unittest.TestCase):
    def test_new_upstream_release_fixes(self):
        r = rec(sid=("resolved", "1.2.4-1", "1.2.5-1"))
        self.assertEqual(b.evaluate("1.2.4", r), {"status": "fixed", "fixed": "1.2.4"})
        self.assertEqual(b.evaluate("1.2.3", r), {"status": "vulnerable", "fixed": "1.2.4"})

    def test_distro_patch(self):
        # Debian patched 1.2.3: Arch's 1.2.3 is affected, 1.2.4 is not.
        r = rec(sid=("resolved", "1.2.3-3", "1.2.3-3"))
        self.assertEqual(b.evaluate("1.2.3", r), {"status": "unfixed", "upto": "1.2.3"})
        self.assertEqual(b.evaluate("1.2.4", r), {"status": "fixed", "upto": "1.2.3"})
        # Recent CVE: whether 1.2.4 has the fix is unknown, so only Arch's current version is safe.
        self.assertEqual(b.evaluate("1.2.4", r, recent=True), {"status": "fixed", "fixed": "1.2.4"})

    def test_really_downgrade(self):
        # xz CVE-2024-3094: Debian "fixed" 5.6.1 by going back to 5.4.5.
        r = rec(sid=("resolved", "5.6.1+really5.4.5-1", "5.8.1-1"))
        self.assertEqual(b.evaluate("5.6.1", r), {"status": "unfixed", "upto": "5.6.1"})
        self.assertTrue(c.affects("5.6.1-1", b.evaluate("5.8.1", r)))

    def test_not_affected(self):
        self.assertIsNone(b.evaluate("1.0", rec(sid=("resolved", "0", "1.0-1"))))

    def test_open(self):
        r = rec(sid=("open", None, "3.14.8-1"))
        self.assertEqual(b.evaluate("3.14.8", r), {"status": "unfixed"})
        self.assertEqual(b.evaluate("3.15.0", r), {"status": "uncertain"})  # newer than anything Debian assessed

    def test_exact_version_open_beats_fix_elsewhere(self):
        # libsixel: sid moved to another line (epoch 1:1.8.7), trixie's 1.10.5 is still vulnerable.
        r = rec(sid=("resolved", "1:1.8.7-r2-1", "1:1.8.7-r2-1"), trixie=("open", None, "1.10.5-1"))
        self.assertEqual(b.evaluate("1.10.5", r), {"status": "unfixed"})

    def test_own_line_fix(self):
        # nodejs 20.x: fixed by a new upstream release in stable on Arch's line, sid is on 24.x.
        r = rec(sid=("resolved", "24.19.0+dfsg-1", "24.21.0+dfsg-1"), trixie=("resolved", "20.19.6+dfsg-1~deb13u1", "20.19.6+dfsg-1~deb13u1"))
        self.assertEqual(b.evaluate("20.19.6", r), {"status": "fixed", "fixed": "20.19.6"})
        self.assertEqual(b.evaluate("20.19.5", r), {"status": "vulnerable", "fixed": "20.19.6"})


class Kernel(unittest.TestCase):
    RULES = [  # CVE-2026-46110 as the kernel CNA writes it
        {"version": "6.7", "status": "affected"},
        {"version": "0", "lessThan": "6.7", "status": "unaffected", "versionType": "semver"},
        {"version": "6.12.88", "lessThanOrEqual": "6.12.*", "status": "unaffected", "versionType": "semver"},
        {"version": "6.18.30", "lessThanOrEqual": "6.18.*", "status": "unaffected", "versionType": "semver"},
        {"version": "7.1", "lessThanOrEqual": "*", "status": "unaffected", "versionType": "original_commit_for_fix"},
    ]

    def test_lines(self):
        self.assertEqual(b.cna_evaluate("6.18.56", self.RULES), {"status": "fixed", "fixed": "6.18.30"})
        self.assertEqual(b.cna_evaluate("6.18.20", self.RULES), {"status": "vulnerable", "fixed": "6.18.30"})
        self.assertEqual(b.cna_evaluate("7.2.9", self.RULES), {"status": "fixed", "fixed": "7.1"})
        self.assertEqual(b.cna_evaluate("7.0.3", self.RULES), {"status": "vulnerable"})  # fixed only on newer lines
        self.assertIsNone(b.cna_evaluate("6.5.1", self.RULES))


class Mozilla(unittest.TestCase):
    RULES = [  # CVE-2026-109732, Thunderbird
        {"version": "153.5", "lessThanOrEqual": "153.*", "status": "unaffected", "versionType": "rpm"},
        {"version": "158", "lessThanOrEqual": "*", "status": "unaffected", "versionType": "rpm"},
    ]

    def test_release_and_esr(self):
        self.assertEqual(b.cna_evaluate("157.0.1", self.RULES, newer_line_fixes=True), {"status": "vulnerable", "fixed": "158"})
        self.assertEqual(b.cna_evaluate("158.0", self.RULES, newer_line_fixes=True), {"status": "fixed", "fixed": "158"})
        self.assertEqual(b.cna_evaluate("153.4.0", self.RULES, newer_line_fixes=True), {"status": "vulnerable", "fixed": "153.5"})


class ArchPackaging(unittest.TestCase):
    def test_fixes(self):
        commits = [  # oldest first: (message, changed files)
            ("upgpkg: 1:1.3.1-1: fix CVE-2026-1004\n", "PKGBUILD\n"),          # older pkgver: ignored
            ("upgpkg: 1:1.3.2-1\n", "PKGBUILD\n"),
            ("Mention CVE-2026-1001 in a comment\n", "PKGBUILD\n"),           # no fix verb
            ("Add patch\n", "PKGBUILD\nzlib-1.3.2-cve-2026-1005.patch\n"),
            ("upgpkg: 1:1.3.2-2\n", ".SRCINFO\n"),
            ("Revert fix for CVE-2026-1002\n", "PKGBUILD\n"),
            ("Apply unreleased upstream patch for CVE-2026-85091\n", "PKGBUILD\n"),
            ("upgpkg: 1:1.3.2-4\n", ".SRCINFO\n"),
        ]
        srcinfo = "source = zlib-1.3.2-CVE-2026-1006.patch::https://example.org\n"
        self.assertEqual(b.arch_fixes("1:1.3.2-4", commits, srcinfo),
                         {"CVE-2026-1005": "1:1.3.2-2", "CVE-2026-85091": "1:1.3.2-4", "CVE-2026-1006": "1:1.3.2-4"})

    def test_release_tags(self):
        import os, tempfile
        with tempfile.TemporaryDirectory() as d:
            for repo, line in [("core-x86_64", "zlib 1:1.3.2-4 1-1.3.2-4 3d37"), ("extra-testing-x86_64", "zlib 1:1.3.2-5 1-1.3.2-5 aaaa"),
                               ("multilib-x86_64", "lib32-zlib 1.3.2-1 1.3.2-1 8bcb")]:
                os.makedirs(os.path.join(d, repo))
                with open(os.path.join(d, repo, line.split()[0]), "w") as f:
                    f.write(line + "\n")
            self.assertEqual(b.release_tags(d), {"zlib": "1-1.3.2-4", "lib32-zlib": "1.3.2-1"})

    def test_gitlab_path(self):
        self.assertEqual([b.gitlab_path(n) for n in ("libsigc++", "gtk2+extra", "tree", "zlib")],
                         ["libsigcplusplus", "gtk2-extra", "unix-tree", "zlib"])


class Refine(unittest.TestCase):
    def feed(self):
        return {"stats": {"pkgbases": 2}, "pkgbases": {"zlib": {"version": "1:1.3.2-4", "issues": [
            {"id": "CVE-A", "status": "unfixed", "upto": "1:1.3.2"},
            {"id": "CVE-B", "status": "fixed", "fixed": "1:1.3.2"},
            {"id": "CVE-C", "status": "fixed", "fixed": "1:1.3.1"}]}}}

    def test_arch_patch_and_history(self):
        prev = {"pkgbases": {"zlib": {"version": "1:1.3.2-3", "issues": [
            {"id": "CVE-B", "status": "vulnerable", "fixed": "1:1.3.2"},
            {"id": "CVE-C", "status": "fixed", "fixed": "1:1.3.1", "since": "1:1.3.1-2"}]}}}
        f = self.feed()
        b.refine(f, {}, {"zlib": {"CVE-A": "1:1.3.2-4"}}, prev)
        got = {i["id"]: i for i in f["pkgbases"]["zlib"]["issues"]}
        self.assertEqual(got["CVE-A"], {"id": "CVE-A", "status": "fixed", "via": "Arch patch", "since": "1:1.3.2-4"})
        self.assertEqual(got["CVE-B"]["since"], "1:1.3.2-4")   # open last run, fixed now
        self.assertEqual(got["CVE-C"]["since"], "1:1.3.1-2")   # carried over
        self.assertTrue(c.affects("1:1.3.2-3", got["CVE-A"]))  # the build before Arch's patch
        self.assertFalse(c.affects("1:1.3.2-4", got["CVE-A"]))
        self.assertEqual(f["stats"]["unfixed"], 0)

    def test_first_run_has_no_history(self):
        f = self.feed()
        b.refine(f, {}, {}, None)
        self.assertNotIn("since", f["pkgbases"]["zlib"]["issues"][1])


class Client(unittest.TestCase):
    FEED = {"generated_at": 0, "packages": {"foo": "foo", "bar": "bar"}, "pkgbases": {"foo": {"version": "2.0-1", "issues": [
        {"id": "CVE-1", "status": "fixed", "fixed": "1.5"},
        {"id": "CVE-2", "status": "vulnerable", "fixed": "2.1"},
        {"id": "CVE-3", "status": "uncertain"},
        {"id": "CVE-4", "status": "unfixed", "minor": True},
        {"id": "CVE-5", "status": "fixed", "via": "Arch patch", "since": "2.0-1"}]}}}

    def test_groups_and_exit(self):
        r = c.assess([("foo", "1.0-1"), ("bar", "1-1"), ("yay", "12-1")], self.FEED)
        self.assertEqual([(f["group"], f["issues"]) for f in r["findings"]],
                         [("upgrade", ["CVE-1", "CVE-5"]), ("vulnerable", ["CVE-2"]), ("uncertain", ["CVE-3"])])
        self.assertEqual((r["foreign"], r["nodata"]), (["yay"], ["bar"]))
        self.assertEqual(c.exit_status(r), 1)
        only = c.assess([("foo", "2.1-1")], self.FEED)
        self.assertEqual(c.exit_status(only), 3)
        self.assertEqual(c.exit_status(c.assess([("bar", "1-1")], self.FEED)), 0)


if __name__ == "__main__":
    unittest.main()
