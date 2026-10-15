"""Turn raw text into the forms the rules should look at."""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

# Cyrillic/Greek letters that look like Latin ones (written as escapes so copy-paste is safe).
_HOMOGLYPHS = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u0501": "d", "\u0261": "g",
    "\u03b1": "a", "\u03bf": "o", "\u03b5": "e", "\u03bd": "v", "\u03b9": "i",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_WS = re.compile(r"\s+")

MAX_B64_CANDIDATES = 5
MAX_B64_ATTEMPTS = 50
MAX_B64_CHARS = 4000


@dataclass
class Normalized:
    clean: str                                              # NFKC, invisible chars removed, original case
    variants: dict[str, str] = field(default_factory=dict)  # "plain" first, then "leet", "base64"
    zero_width_removed: int = 0
    homoglyphs_replaced: int = 0


def _strip_invisible(text: str) -> tuple[str, int]:
    """Remove Unicode 'format' characters (zero-width space/joiner, BOM, bidi controls)."""
    kept = [ch for ch in text if unicodedata.category(ch) != "Cf"]
    return "".join(kept), len(text) - len(kept)


def _fold(text: str) -> tuple[str, int]:
    folded = text.casefold()
    swapped = folded.translate(_HOMOGLYPHS)
    changed = sum(1 for a, b in zip(folded, swapped) if a != b)
    return _WS.sub(" ", swapped).strip(), changed


def _decode_base64(text: str) -> list[str]:
    out: list[str] = []
    for attempt, m in enumerate(_B64.finditer(text)):
        if attempt >= MAX_B64_ATTEMPTS or len(out) >= MAX_B64_CANDIDATES:
            break
        chunk = m.group(0)[:MAX_B64_CHARS]
        chunk += "=" * (-len(chunk) % 4)
        try:
            decoded = base64.b64decode(chunk, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        letters = sum(c.isalpha() or c.isspace() for c in decoded)
        if decoded and letters / len(decoded) >= 0.8:       # real text, not random bytes
            out.append(decoded)
    return out


def normalize(text: str) -> Normalized:
    nfkc = unicodedata.normalize("NFKC", text)
    clean, hidden = _strip_invisible(nfkc)
    plain, homoglyphs = _fold(clean)

    variants = {"plain": plain}
    leet = plain.translate(_LEET)
    if leet != plain:
        variants["leet"] = leet
    decoded = _decode_base64(clean)          # case-sensitive, so it reads `clean`, not `plain`
    if decoded:
        variants["base64"] = _WS.sub(" ", " ".join(d.casefold() for d in decoded)).strip()

    return Normalized(clean=clean, variants=variants,
                      zero_width_removed=hidden, homoglyphs_replaced=homoglyphs)