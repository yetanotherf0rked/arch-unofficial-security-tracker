"""The page's JavaScript must agree with libalpm and arch_cve_check.py (needs node)."""

import json
import random
import shutil
import subprocess
import tempfile
import unittest

import arch_cve_check as c
from tests.test_tracker import Client

ALPHABET = "0123456789abcprz._-+~:"


def rand_version(rng: random.Random) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 12)))


@unittest.skipUnless(shutil.which("node"), "node not installed")
class Site(unittest.TestCase):
    def test_js_matches_python(self):
        rng = random.Random(1)
        pairs = [(rand_version(rng), rand_version(rng)) for _ in range(20000)]
        pairs += [("1.9.13.p2-1", "1.9.13.p3"), ("7.2.9.arch1-1", "7.2.10"), ("1:1.0", "2.0"), ("2026_10_09-1", "20261009")]
        versions = [a for a, _ in pairs[:3000]] + ["1.9.17p2-6", "2.1.13-stable", "1.0~rc1", "8.3_p1-2", "1:2.3_p1-4"]
        feed = Client.FEED
        installed = [["foo", "1.0-1"], ["bar", "1-1"], ["yay", "12-1"]]
        want = [[f["package"], f["group"], f["issues"]] for f in c.assess([tuple(i) for i in installed], feed)["findings"]]
        vectors = {"vercmp": [[a, b, c.vercmp(a, b)] for a, b in pairs],
                   "norm": [[v, c.norm(v)] for v in versions], "key": [[v, c.key(v)] for v in versions],
                   "assess": {"installed": installed, "feed": feed, "want": want}}
        with tempfile.NamedTemporaryFile("w", suffix=".json") as f:
            json.dump(vectors, f)
            f.flush()
            r = subprocess.run(["node", "tests/site.test.mjs", f.name], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr[-2000:])
