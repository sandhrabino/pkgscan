"""Signal 8 - Typosquatting (name similarity against popular packages)."""
from __future__ import annotations

import unicodedata

from pkgscan.config import read_list
from pkgscan.context import ScanContext
from pkgscan.models import ProducerOutput
from pkgscan.producers.base import Producer

HOMOGLYPHS = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
              "ο": "o", "α": "a", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k"}
LEET = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
VISUAL = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m")]
COMPANIES = ["google", "microsoft", "amazon", "aws", "facebook", "meta", "apple", "github", "paypal", "stripe",
             "openai", "anthropic", "azure", "netflix", "nvidia"]
QWERTY = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]


def _adjacent(a: str, b: str) -> bool:
    for row in QWERTY:
        i, j = row.find(a), row.find(b)
        if i >= 0 and j >= 0 and abs(i - j) == 1:
            return True
    return False


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalize(name: str) -> str:
    n = "".join(HOMOGLYPHS.get(c, c) for c in name.lower())
    n = unicodedata.normalize("NFKD", n).encode("ascii", "ignore").decode()
    n = "".join(LEET.get(c, c) for c in n)
    for a, b in VISUAL:
        n = n.replace(a, b)
    return n.replace("_", "-").replace(".", "-")


def strip_scope(name: str) -> str:
    return name.split("/", 1)[1] if name.startswith("@") and "/" in name else name


class Typosquatting(Producer):
    name = "typosquatting"
    title = "Typosquatting"
    signal_ref = "8"

    def run(self, ctx: ScanContext) -> ProducerOutput:
        out = ProducerOutput()
        name = ctx.pkg.name
        top = read_list("top_npm.txt" if ctx.pkg.ecosystem == "npm" else "top_pypi.txt")
        if name.lower() in {t.lower() for t in top}:
            out.facts["is_popular_name"] = True
            return out
        if any(ord(c) > 127 for c in name):
            out.signals.append(self.sig("non-ascii-name", "high", "Package name contains non-ASCII (homoglyph) characters",
                                        category="typosquat", evidence=[name.encode("unicode_escape").decode()]))
        base = strip_scope(name)
        nb = normalize(base)
        maxd = ctx.cfg["thresholds"]["typosquat_max_distance"]
        hits = []
        for t in top:
            tb = strip_scope(t)
            if tb == base or len(tb) < 4:
                continue
            nt = normalize(tb)
            if nb == nt:
                hits.append((t, "confusable characters (homoglyph/leet/visual)"))
                continue
            d = levenshtein(base.lower(), tb.lower())
            limit = 1 if len(tb) <= 5 else maxd
            if d <= limit:
                why = f"edit distance {d}"
                if len(base) == len(tb) and d == 1:
                    diff = [(x, y) for x, y in zip(base.lower(), tb.lower()) if x != y]
                    if diff and _adjacent(*diff[0]):
                        why = "adjacent-key typo"
                elif len(base) == len(tb) + 1:
                    why = "extra character"
                elif len(base) + 1 == len(tb):
                    why = "missing character"
                hits.append((t, why))
            elif base.lower().replace("-", "") == tb.lower().replace("-", "") or \
                    base.lower() in (f"{tb}-js", f"{tb}js", f"node-{tb}", f"{tb}-py", f"py{tb}", f"python-{tb}"):
                hits.append((t, "separator/affix variant"))
        for t, why in hits[:5]:
            out.signals.append(self.sig("typosquat-candidate", "medium", f"Name resembles popular package `{t}` ({why})",
                                        category="typosquat"))
        low = base.lower()
        brands = [c for c in COMPANIES if c in low]
        if brands and not name.startswith("@"):
            out.signals.append(self.sig("brand-in-name", "low", f"Unscoped name uses brand(s) {brands}",
                                        category="typosquat"))
        out.facts["similar_to"] = [t for t, _ in hits]
        return out
