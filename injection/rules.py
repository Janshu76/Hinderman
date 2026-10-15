"""Layer 1: rule engine."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from contracts import TYPE_CATEGORY   # adjust the import to wherever contracts.py lives

from . import config
from .normalize import Normalized

PATTERNS_FILE = Path(__file__).parent / "data" / "patterns.yaml"
_FLAGS = re.IGNORECASE | re.DOTALL | re.MULTILINE
_VALID_SOURCES = {"user", "document"}


@dataclass(frozen=True)
class Rule:
    id: str
    type: str
    weight: float
    regex: re.Pattern
    description: str
    sources: tuple[str, ...]
    not_regex: re.Pattern | None


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    type: str
    weight: float
    variant: str          # "plain", "leet", "base64" or "meta"
    description: str


def load_rules(path: Path = PATTERNS_FILE) -> list[Rule]:
    """Load and validate the rules. Fails loudly at startup, never silently at request time."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]
    rules: list[Rule] = []
    seen: set[str] = set()
    for item in raw:
        rid = item["id"]
        if rid in seen:
            raise ValueError(f"duplicate rule id {rid}")
        seen.add(rid)
        if TYPE_CATEGORY.get(item["type"]) != "INJECTION":
            raise ValueError(f"{rid}: {item['type']!r} is not an INJECTION type in contracts")
        weight = float(item["weight"])
        if not 0 < weight <= 1:
            raise ValueError(f"{rid}: weight must be in (0, 1]")
        sources = tuple(item.get("sources", ["user", "document"]))
        if not set(sources) <= _VALID_SOURCES:
            raise ValueError(f"{rid}: bad sources {sources}")
        rules.append(Rule(
            id=rid,
            type=item["type"],
            weight=weight,
            regex=re.compile(item["regex"], _FLAGS),
            description=item["description"],
            sources=sources,
            not_regex=re.compile(item["not_regex"], _FLAGS) if item.get("not_regex") else None,
        ))
    return rules


def noisy_or(weights) -> float:
    """Combine independent signals: 0.6 and 0.5 give 1 - 0.4*0.5 = 0.8. Many weak hits add up."""
    miss = 1.0
    for w in weights:
        miss *= 1.0 - w
    return 1.0 - miss


def _first_match(rule: Rule, text: str):
    for m in rule.regex.finditer(text):
        if rule.not_regex and rule.not_regex.search(m.group(0)):
            continue
        return m
    return None


def scan(norm: Normalized, source: str, rules: list[Rule]) -> list[RuleHit]:
    hits: list[RuleHit] = []
    for rule in rules:
        if source not in rule.sources:
            continue
        for variant, text in norm.variants.items():      # "plain" is tried first
            if _first_match(rule, text):
                hits.append(RuleHit(rule.id, rule.type, rule.weight, variant, rule.description))
                break
    return _add_meta_hits(hits, norm, source)


def _add_meta_hits(hits: list[RuleHit], norm: Normalized, source: str) -> list[RuleHit]:
    """Extra evidence, only added when a real rule already fired."""
    if not hits:
        return hits
    top = max(hits, key=lambda h: h.weight)
    out = list(hits)
    if all(h.variant != "plain" for h in hits):
        out.append(RuleHit("R-OBFUSCATED", top.type, 0.3, "meta",
                           "attack phrase only visible after decoding or de-leeting"))
    if source == "document" and norm.zero_width_removed >= config.HIDDEN_CHARS_THRESHOLD:
        out.append(RuleHit("R-HIDDEN-CHARS", top.type, 0.2, "meta",
                           "many invisible characters hidden in the document"))
    return out