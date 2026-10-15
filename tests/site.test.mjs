// node tests/site.test.mjs VECTORS.json — the page's vercmp/norm/key against libalpm and arch_cve_check.py.
import { readFileSync } from "node:fs";
import { vercmp } from "../site/vercmp.js";
import { norm, key, assess } from "../site/app.js";

const v = JSON.parse(readFileSync(process.argv[2]));  // written by tests/test_site.py
let failed = 0;
const check = (what, got, want) => { if (got !== want) { failed++; console.error(`${what}: got ${got}, want ${want}`); } };
for (const [a, b, want] of v.vercmp) check(`vercmp(${a}, ${b})`, vercmp(a, b), want);
for (const [raw, want] of v.norm) check(`norm(${raw})`, norm(raw), want);
for (const [raw, want] of v.key) check(`key(${raw})`, key(raw), want);
check("assess", JSON.stringify(assess(v.assess.installed, v.assess.feed).findings.map(f => [f.package, f.group, f.issues])),
      JSON.stringify(v.assess.want));
if (failed) { console.error(`${failed} failure(s)`); process.exit(1); }
console.log(`ok: ${v.vercmp.length} vercmp, ${v.norm.length} norm, ${v.key.length} key vectors, assess()`);
