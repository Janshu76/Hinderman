"""Prompt-injection defence (M3). M1 imports: score, canary, warm_up."""
from __future__ import annotations

from typing import Literal

from contracts import InjectionResult   # adjust the import to wherever contracts.py lives

from . import config
from .canary import Canary
from .classifier import InjectionClassifier
from .combiner import combine
from .normalize import Normalized, normalize
from .rules import load_rules, scan


class Scorer:
    def __init__(self) -> None:
        self._rules = load_rules()           # validated once at import
        self._clf = InjectionClassifier()    # the model itself loads lazily

    def warm_up(self) -> None:
        """Call once at gateway startup so the first real request does not pay the model load."""
        if config.get_mode() != "rules":
            _ = self._clf.available

    @staticmethod
    def _model_input(norm: Normalized) -> str:
        decoded = norm.variants.get("base64")
        return f"{norm.clean}\n{decoded}" if decoded else norm.clean

    def score(self, text: str, source: Literal["user", "document"] = "user") -> InjectionResult:
        mode = config.get_mode()
        norm = normalize(text or "")
        hits = scan(norm, source, self._rules) if mode != "model" else []
        model_score = self._clf.score(self._model_input(norm)) if mode != "rules" else None
        return combine(hits, model_score, source, mode)


scorer = Scorer()
canary = Canary()
score = scorer.score          # matches the InjectionScorer Protocol: score(text, source)
warm_up = scorer.warm_up

__all__ = ["score", "scorer", "canary", "warm_up"]