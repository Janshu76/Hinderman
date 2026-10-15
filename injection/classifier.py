"""Layer 2: Hugging Face prompt-injection classifier with a safe fallback."""
from __future__ import annotations

import logging

from . import config

log = logging.getLogger(__name__)

# The model has a "safe" class and an "injection" class. Anything that is not
# safe counts as injection, so this keeps working if the label names differ.
# Check model.config.id2label once when you first load the model.
SAFE_LABELS = {"SAFE", "LABEL_0", "BENIGN", "LEGIT"}


class InjectionClassifier:
    def __init__(self, model_name: str | None = None, pipe=None) -> None:
        self.model_name = model_name or config.MODEL_NAME
        self._pipe = pipe            # a ready pipeline can be injected, which keeps tests light
        self._failed = False

    def _load(self) -> None:
        if self._pipe is not None or self._failed:
            return
        try:
            from transformers import pipeline          # imported here so rules-only mode needs no torch
            self._pipe = pipeline("text-classification", model=self.model_name, device=-1)
            self._pipe("warm up")                      # the first call is slow
        except Exception as exc:                       # missing package, no network, model not cached
            log.warning("injection classifier unavailable (%s); using rules only", type(exc).__name__)
            self._pipe = None
            self._failed = True

    @property
    def available(self) -> bool:
        self._load()
        return self._pipe is not None

    def _windows(self, text: str) -> list[str]:
        tok = self._pipe.tokenizer
        ids = tok(text, add_special_tokens=False, truncation=False, verbose=False)["input_ids"]
        size = config.MAX_TOKENS - 2
        step = max(size - config.STRIDE_TOKENS, 1)
        windows: list[str] = []
        start = 0
        while start < len(ids) and len(windows) < config.MAX_WINDOWS:
            windows.append(tok.decode(ids[start:start + size]))
            if start + size >= len(ids):
                break
            start += step
        return windows or [text]

    @staticmethod
    def _p_injection(labels: list[dict]) -> float:
        total = sum(float(x["score"]) for x in labels if str(x["label"]).upper() not in SAFE_LABELS)
        return min(total, 1.0)

    def score(self, text: str) -> float | None:
        """Highest injection probability over all windows, or None if the model is unavailable."""
        if not self.available:
            return None
        if not text.strip():
            return 0.0
        try:
            outputs = self._pipe(self._windows(text), truncation=True,
                                 max_length=config.MAX_TOKENS, top_k=None)
            outputs = [o if isinstance(o, list) else [o] for o in outputs]
            return max(self._p_injection(o) for o in outputs)
        except Exception as exc:
            log.warning("injection classifier failed (%s); using rules only", type(exc).__name__)
            return None