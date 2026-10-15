"""Full evaluation through the gateway.

    python -m eval.run_eval                 # dev split
    python -m eval.run_eval --split heldout # only once, for the final report
"""
from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from .ablation import load_cases
from .client import GatewayClient
from .metrics import summarise

RESULTS_DIR = Path(__file__).parent / "results"


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m eval.run_eval")
    parser.add_argument("--split", choices=["dev", "heldout"], default="dev")
    args = parser.parse_args()

    cases = load_cases(split=args.split)
    client = GatewayClient()
    results = []
    for i, case in enumerate(cases, 1):
        result = client.run_case(case)
        results.append(result)
        mark = "ok " if result.correct else "MISS"
        print(f"[{i:>3}/{len(cases)}] {mark} {case.id:<14} -> {result.action_taken}")

    summary = summarise(results)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    RESULTS_DIR.mkdir(exist_ok=True)
    out_json = RESULTS_DIR / f"{args.split}-{stamp}.json"
    out_csv = RESULTS_DIR / f"{args.split}-{stamp}.csv"
    out_json.write_text(json.dumps({"summary": summary,
                                    "results": [r.model_dump() for r in results]}, indent=2))
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].model_dump().keys()))
        writer.writeheader()
        for r in results:
            row = r.model_dump()
            row["found_types"] = ";".join(row["found_types"])
            row["policy_ids"] = ";".join(row["policy_ids"])
            row["denied_doc_ids"] = ";".join(row["denied_doc_ids"])
            row["latency_ms"] = json.dumps(row["latency_ms"])
            writer.writerow(row)

    print("\n=== summary ===")
    print(json.dumps({k: v for k, v in summary.items() if k != "per_group"}, indent=2))
    print(f"\nwritten: {out_json}\n         {out_csv}")


if __name__ == "__main__":
    main()