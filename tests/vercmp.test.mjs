// node tests/vercmp.test.mjs — the page's vercmp against pacman's own test cases.
import { readFileSync } from "node:fs";
import { vercmp } from "../site/vercmp.js";
import { assess } from "../site/assess.js";

const { cases } = JSON.parse(readFileSync(new URL("./vercmp_vectors.json", import.meta.url)));
let failed = 0;
for (const [a, b, want] of cases) {
  for (const [x, y, w] of [[a, b, want], [b, a, -want]]) {
    const got = vercmp(x, y);
    if (got !== w) { failed++; console.error(`vercmp(${x}, ${y}) = ${got}, want ${w}`); }
  }
}

// assess() on a feed written by the Python test fixtures' shape.
const feed = {
  packages: { foo: "foo", "foo-docs": "foo", quiet: "quiet" },
  pkgbases: {
    foo: {
      version: "1:2.0-1",
      fixed: [{ fixed: "1:1.9.2", severity: "Critical", ids: ["CVE-1"] }],
      issues: [
        { id: "CVE-2", status: "vulnerable", fixed: "1:2.1", fix: ["2.1"], severity: "Unknown", reason: "below-fix" },
        { id: "CVE-3", status: "unfixed", severity: "Low", reason: "no-fix" },
        { id: "CVE-4", status: "unfixed", severity: "Low", minor: true },
      ],
    },
  },
};
const res = assess([
  { name: "foo-docs", version: "1:1.9-1" }, { name: "quiet", version: "1.0-1" }, { name: "yay", version: "12-1" },
], feed, false);
const groups = res.findings.map(f => `${f.package}:${f.group}:${f.issues.join("+")}`).sort();
const want = ["foo-docs:unfixed:CVE-3", "foo-docs:upgrade:CVE-1", "foo-docs:vulnerable:CVE-2"];
if (JSON.stringify(groups) !== JSON.stringify(want)) { failed++; console.error("assess:", groups); }
if (JSON.stringify([res.foreign, res.uncovered]) !== JSON.stringify([["yay"], ["quiet"]])) {
  failed++; console.error("coverage:", res.foreign, res.uncovered);
}
const newer = assess([{ name: "foo", version: "1:2.1-1" }], feed, false).findings.map(f => f.group).sort();
if (JSON.stringify(newer) !== JSON.stringify(["unfixed"])) { failed++; console.error("newer build:", newer); }

if (failed) { console.error(`${failed} failure(s)`); process.exit(1); }
console.log(`ok — ${cases.length * 2} vercmp comparisons, assess()`);
