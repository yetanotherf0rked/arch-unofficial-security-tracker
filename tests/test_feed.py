"""Feed assembly (archsec.build) and the client (archsec.check) end to end."""

import io
import json
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from archsec import build, check

NOW = int(time.time())
DAY = 86400


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def debian(cve, name, fixed=None, published=NOW - 10 * DAY, versions=(), urgency=None, vector=None):
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    a = {"package": {"ecosystem": "Debian:14", "name": name},
         "ranges": [{"type": "ECOSYSTEM", "events": events}], "versions": list(versions)}
    if urgency:
        a["ecosystem_specific"] = {"urgency": urgency}
    r = {"id": f"DEBIAN-{cve}", "upstream": [cve], "published": iso(published),
         "details": f"{cve} in {name}", "affected": [a]}
    if vector:
        r["severity"] = [{"type": "CVSS_V3", "score": vector}]
    return r


PACKAGES = [
    {"name": "foo", "base": "foo", "version": "1:2.0-1", "repo": "extra", "builddate": NOW - 30 * DAY},
    {"name": "foo-docs", "base": "foo", "version": "1:2.0-1", "repo": "extra", "builddate": NOW - 30 * DAY},
    {"name": "bar", "base": "bar", "version": "5.1-2", "repo": "core", "builddate": NOW - 30 * DAY},
    {"name": "quiet", "base": "quiet", "version": "1.0-1", "repo": "core", "builddate": NOW - 30 * DAY},
]
CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
INDEX = {
    ("Debian", "foo"): [
        debian("CVE-2026-0001", "foo", "1:1.9.2-1", vector=CRIT),     # fixed in Arch (1.9.2)
        debian("CVE-2026-0002", "foo", "2.1-1"),                       # Arch below fix
        debian("CVE-2026-0003", "foo", versions=["1.8-1", "2.0-1"]),   # unfixed
        debian("CVE-2026-0004", "foo", versions=["2.0-1"], urgency="unimportant"),
        debian("CVE-2015-0005", "foo", "1:0.5-3", published=NOW - 3000 * DAY),  # ancient patch
    ],
    ("Debian", "bar"): [debian("CVE-2026-0010", "bar", "5.0-1")],
}


class Build(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.feed = build.build(PACKAGES, INDEX, {}, now=NOW)

    def test_structure(self):
        f = self.feed
        self.assertEqual(f["packages"], {"foo": "foo", "foo-docs": "foo", "bar": "bar", "quiet": "quiet"})
        self.assertEqual(set(f["pkgbases"]), {"foo", "bar"})  # quiet has no records: not covered
        foo = f["pkgbases"]["foo"]
        self.assertEqual(foo["sources"], ["Debian:foo"])
        self.assertEqual(sorted(foo["packages"]), ["foo", "foo-docs"])

    def test_issue_statuses(self):
        foo = self.feed["pkgbases"]["foo"]
        by_id = {i["id"]: i for i in foo["issues"]}
        self.assertEqual(by_id["CVE-2026-0002"]["status"], "vulnerable")
        self.assertEqual(by_id["CVE-2026-0002"]["fixed"], "1:2.1")  # upstream fix written with Arch's epoch
        self.assertEqual(by_id["CVE-2026-0003"]["status"], "unfixed")
        self.assertTrue(by_id["CVE-2026-0004"]["minor"])
        # fixed issues are grouped by the Arch version that fixes them
        self.assertEqual(foo["fixed"], [{"fixed": "1:1.9.2", "severity": "Critical",
                                         "published": foo["fixed"][0]["published"], "ids": ["CVE-2026-0001"]}])

    def test_arch_audit_format(self):
        avgs = build.arch_audit_feed(self.feed["pkgbases"])
        keys = {"name", "packages", "status", "severity", "type", "affected", "fixed", "ticket", "issues", "advisories"}
        for a in avgs:
            self.assertEqual(set(a), keys)
            self.assertIn(a["status"], ("Fixed", "Vulnerable", "Unknown"))
            self.assertIn(a["severity"], ("Unknown", "Low", "Medium", "High", "Critical"))
        fixed = [a for a in avgs if a["status"] == "Fixed" and "foo" in a["packages"]]
        self.assertEqual([(a["fixed"], a["issues"]) for a in fixed], [("1:1.9.2", ["CVE-2026-0001"])])
        vuln = [a for a in avgs if a["status"] == "Vulnerable" and "foo" in a["packages"]][0]
        self.assertIsNone(vuln["fixed"])
        self.assertNotIn("CVE-2026-0004", vuln["issues"])  # unimportant left out


class Client(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.feed = build.build(PACKAGES, INDEX, {}, now=NOW)

    def findings(self, installed, **kw):
        res = check.assess(installed, self.feed, **kw)
        return res, {(f["package"], f["group"]): f for f in res["findings"]}

    def test_up_to_date(self):
        res, f = self.findings([{"name": "foo", "version": "1:2.0-1", "base": "foo"}])
        self.assertEqual(set(f), {("foo", "vulnerable"), ("foo", "unfixed")})
        self.assertNotIn("CVE-2026-0004", f[("foo", "unfixed")]["issues"])

    def test_outdated_needs_upgrade(self):
        res, f = self.findings([{"name": "foo-docs", "version": "1:1.9-1", "base": "foo"}])
        up = f[("foo-docs", "upgrade")]
        self.assertEqual((up["issues"], up["fixed"], up["repo_version"]), (["CVE-2026-0001"], "1:1.9.2", "1:2.0-1"))

    def test_newer_build_has_upstream_fix(self):
        res, f = self.findings([{"name": "foo", "version": "1:2.1-1", "base": "foo"}])
        self.assertNotIn(("foo", "vulnerable"), f)
        self.assertIn(("foo", "unfixed"), f)

    def test_minor_on_request(self):
        res, f = self.findings([{"name": "foo", "version": "1:2.0-1", "base": "foo"}], include_minor=True)
        self.assertIn("CVE-2026-0004", f[("foo", "unfixed")]["issues"])

    def test_coverage(self):
        res, f = self.findings([
            {"name": "quiet", "version": "1.0-1", "base": "quiet"},
            {"name": "yay", "version": "12.0-1", "base": "yay"},
            {"name": "bar", "version": "5.1-2", "base": "bar"},
        ])
        self.assertEqual((res["foreign"], res["uncovered"], f), (["yay"], ["quiet"], {}))

    def test_pacman_q_list_maps_names_to_bases(self):
        installed = check.read_package_list(["foo-docs 1:1.9-1", "", "yay 12.0-1"])
        res, f = self.findings(installed)
        self.assertIn(("foo-docs", "upgrade"), f)
        self.assertEqual(res["foreign"], ["yay"])

    def test_cli_reads_local_db_and_sets_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "feed.json").write_text(json.dumps(self.feed))
            pkg = tmp / "db" / "local" / "bar-5.1-2"
            pkg.mkdir(parents=True)
            (pkg / "desc").write_text("%NAME%\nbar\n\n%VERSION%\n5.1-2\n\n%BASE%\nbar\n\n")
            args = ["--feed", str(tmp / "feed.json"), "-b", str(tmp / "db"), "--color", "never"]
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(check.main(args), 0)
            self.assertIn("No known CVE", out.getvalue())

            pkg2 = tmp / "db" / "local" / "foo-1:1.9-1"
            pkg2.mkdir()
            (pkg2 / "desc").write_text("%NAME%\nfoo\n\n%VERSION%\n1:1.9-1\n\n%BASE%\nfoo\n\n")
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(check.main(args + ["--json"]), 1)
            groups = {f["group"] for f in json.loads(out.getvalue())["findings"]}
            self.assertEqual(groups, {"upgrade", "vulnerable", "unfixed"})


if __name__ == "__main__":
    unittest.main()
