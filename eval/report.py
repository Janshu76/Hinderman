"""Make the report charts from the latest results file. Run after run_eval or run_ablation.

    python -m eval.report
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")                      # no window needed
import matplotlib.pyplot as plt

from .ablation import run_ablation

OUT = Path(__file__).parent / "results"


def ablation_chart(data: dict) -> Path:
    modes = list(data)
    metrics = ["precision", "recall", "f1", "false_positive_rate"]
    width = 0.2
    fig, ax = plt.subplots(figsize=(8, 4.5))
    for i, metric in enumerate(metrics):
        values = [data[m][metric] for m in modes]
        ax.bar([x + i * width for x in range(len(modes))], values, width, label=metric)
    ax.set_xticks([x + 1.5 * width for x in range(len(modes))], modes)
    ax.set_ylim(0, 1.05)
    ax.set_title("Injection detection: rules vs model vs combined")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    path = OUT / "ablation.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


def confusion_chart(data: dict, mode: str = "combined") -> Path:
    c = data[mode]["confusion"]
    grid = [[c["TP"], c["FN"]], [c["FP"], c["TN"]]]
    fig, ax = plt.subplots(figsize=(4, 3.6))
    ax.imshow(grid, cmap="Blues")
    labels = [["TP (caught)", "FN (missed)"], ["FP (wrongly stopped)", "TN (passed)"]]
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{labels[i][j]}\n{grid[i][j]}", ha="center", va="center", fontsize=8)
    ax.set_xticks([0, 1], ["attack", "legitimate"])
    ax.set_yticks([0, 1], ["stopped", "let through"])
    ax.set_title(f"Confusion matrix ({mode})", fontsize=10)
    fig.tight_layout()
    path = OUT / f"confusion_{mode}.png"
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return path


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    data = run_ablation()
    (OUT / "ablation.json").write_text(json.dumps(data, indent=2))
    print("written:", ablation_chart(data), confusion_chart(data))