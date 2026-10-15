// pacman's version ordering — port of libalpm's alpm_pkg_vercmp / rpmvercmp,
// identical to archsec/check.py's vercmp (both are tested against
// tests/vercmp_vectors.json).

const isDigit = c => c >= "0" && c <= "9";
const isAlpha = c => (c >= "a" && c <= "z") || (c >= "A" && c <= "Z");
const isAlnum = c => isDigit(c) || isAlpha(c);

function rpmvercmp(a, b) {
  if (a === b) return 0;
  const la = a.length, lb = b.length;
  let one = 0, two = 0, p1 = 0, p2 = 0;
  while (one < la && two < lb) {
    while (one < la && !isAlnum(a[one])) one++;
    while (two < lb && !isAlnum(b[two])) two++;
    if (!(one < la && two < lb)) break;
    // Different separator lengths decide on their own.
    if (one - p1 !== two - p2) return one - p1 < two - p2 ? -1 : 1;
    p1 = one; p2 = two;
    let isnum;
    if (isDigit(a[p1])) {
      while (p1 < la && isDigit(a[p1])) p1++;
      while (p2 < lb && isDigit(b[p2])) p2++;
      isnum = true;
    } else {
      while (p1 < la && isAlpha(a[p1])) p1++;
      while (p2 < lb && isAlpha(b[p2])) p2++;
      isnum = false;
    }
    let s1 = a.slice(one, p1), s2 = b.slice(two, p2);
    if (!s2) return isnum ? 1 : -1;  // numeric segments are always newer than alpha ones
    if (isnum) {
      s1 = s1.replace(/^0+/, ""); s2 = s2.replace(/^0+/, "");
      if (s1.length !== s2.length) return s1.length > s2.length ? 1 : -1;
    }
    if (s1 !== s2) return s1 < s2 ? -1 : 1;
    one = p1; two = p2;
  }
  if (one >= la && two >= lb) return 0;
  // A remaining alpha string never beats an empty one ("1.0rc" < "1.0").
  if ((one >= la && !(two < lb && isAlpha(b[two]))) || (one < la && isAlpha(a[one]))) return -1;
  return 1;
}

function parseEVR(v) {
  let i = 0;
  while (i < v.length && isDigit(v[i])) i++;
  const dash = v.lastIndexOf("-");
  const hasDash = dash >= i;
  let epoch = "0", start = 0;
  if (i < v.length && v[i] === ":") { epoch = v.slice(0, i) || "0"; start = i + 1; }
  return hasDash ? [epoch, v.slice(start, dash), v.slice(dash + 1)] : [epoch, v.slice(start), null];
}

/** pacman's `vercmp`: -1, 0 or 1. A missing pkgrel on either side is ignored. */
export function vercmp(a, b) {
  if (a === b) return 0;
  const [e1, v1, r1] = parseEVR(a);
  const [e2, v2, r2] = parseEVR(b);
  let ret = rpmvercmp(e1, e2);
  if (ret === 0) {
    ret = rpmvercmp(v1, v2);
    if (ret === 0 && r1 !== null && r2 !== null) ret = rpmvercmp(r1, r2);
  }
  return ret;
}
