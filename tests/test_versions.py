"""Version handling: upstream normalization, Arch formatting, pacman's vercmp, names, severity."""

import json
import unittest
from pathlib import Path

from archsec import names, severity
from archsec.check import vercmp as alpm_vercmp
from archsec.versions import arch_form, split_arch, upstream_version, vercmp

HERE = Path(__file__).parent


class PacmanVercmp(unittest.TestCase):
    def test_vectors(self):
        cases = json.loads((HERE / "vercmp_vectors.json").read_text())["cases"]
        for a, b, expected in cases:
            with self.subTest(a=a, b=b):
                self.assertEqual(alpm_vercmp(a, b), expected)
                self.assertEqual(alpm_vercmp(b, a), -expected)


class Upstream(unittest.TestCase):
    def test_normalize(self):
        for raw, want in [
            ("1:2.3.4-1", "2.3.4"),
            ("2.3.4+dfsg-1+deb12u1", "2.3.4"),
            ("2.0+really1.9-1", "1.9"),
            ("1.36.1-r21", "1.36.1"),
            ("2.11.0beta2", "2.11.0~beta2"),
            ("2026_10_09", "20261009"),
        ]:
            self.assertEqual(upstream_version(raw), want, raw)

    def test_debian_ordering(self):
        self.assertEqual(vercmp("1.0~rc1", "1.0"), -1)
        self.assertEqual(vercmp("1.1.1a", "1.1.1"), 1)
        self.assertEqual(vercmp("154.0.8037.97", "155.0.8059.39"), -1)

    def test_split_arch(self):
        self.assertEqual(split_arch("1:2.3-4"), ("1", "2.3", "4"))
        self.assertEqual(split_arch("2.3"), ("", "2.3", ""))

    def test_arch_form(self):
        self.assertEqual(arch_form("1.0~rc2", "1.0rc1-1"), "1.0rc2")
        self.assertEqual(arch_form("3.1.7", "1:3.1.6-3"), "1:3.1.7")
        self.assertEqual(arch_form("20261009", "2026_10_08-1"), "2026_10_09")
        # pacman orders the result like the release it names
        self.assertEqual(alpm_vercmp("1.0rc1-1", arch_form("1.0~rc2", "1.0rc1-1")), -1)
        self.assertEqual(alpm_vercmp("2026_10_08-1", arch_form("20261009", "2026_10_08-1")), -1)


class Names(unittest.TestCase):
    def test_versioned_and_python(self):
        c = names.candidates("python", "3.14.8", {})
        self.assertIn("python3.14", c["Debian"])
        self.assertIn("python3", c["Alpine"])
        c = names.candidates("python-Jinja_2", "3.1", {})
        self.assertIn("py3-jinja_2", c["Alpine"])
        self.assertEqual(c["PyPI"], ["jinja-2"])

    def test_lib32_and_alias_template(self):
        aliases = {"go": {"Debian": ["golang-{major}.{minor}"]}, "glib2": {"Alpine": []}}
        self.assertIn("golang-1.27", names.candidates("go", "1.27.2", aliases)["Debian"])
        self.assertIn("glib2", names.candidates("lib32-glib2", "2.90.1", aliases)["Debian"])
        self.assertEqual(names.candidates("glib2", "2.90.1", aliases)["Alpine"], [])

    def test_aliases_file_parses(self):
        aliases = names.load_aliases(HERE.parent / "aliases.json")
        self.assertIn("sqlite", aliases)
        for base, fams in aliases.items():
            self.assertTrue(set(fams) <= set(names.FAMILIES), base)


class Severity(unittest.TestCase):
    def test_cvss3(self):
        for vector, score in [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ]:
            self.assertEqual(severity.cvss3_score(vector), score, vector)
        self.assertIsNone(severity.cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"))

    def test_rating(self):
        self.assertEqual([severity.rating(s) for s in (None, 3.9, 4.0, 7.0, 9.0)],
                         ["Unknown", "Low", "Medium", "High", "Critical"])


if __name__ == "__main__":
    unittest.main()
