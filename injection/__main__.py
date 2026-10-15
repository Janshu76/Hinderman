"""CLI:  INJECTION_MODE=rules python -m injection "some text" [--source document]"""
from __future__ import annotations

import argparse
import json
import sys

from . import scorer


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m injection", description="Score text for prompt injection.")
    parser.add_argument("text", nargs="?", help="text to score (reads stdin if omitted)")
    parser.add_argument("--source", choices=["user", "document"], default="user")
    args = parser.parse_args()

    text = args.text if args.text is not None else sys.stdin.read()
    print(json.dumps(scorer.score(text, args.source).model_dump(), indent=2))


if __name__ == "__main__":
    main()