"""Command line: python -m detectors "text to scan"   (or pipe text on stdin)."""
import sys

from .scan import detect_all, mask_preview, mask_text


def main(argv=None, stdin=None, stdout=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout

    text = " ".join(argv) if argv else stdin.read()
    findings = detect_all(text)

    if not findings:
        print("No sensitive data found.", file=stdout)
        return 0

    print(f"Found {len(findings)} item(s):", file=stdout)
    for f in findings:
        preview = mask_preview(text[f.start:f.end])
        print(
            f"  {f.type:<8} {f.category:<10} [{f.start}:{f.end}]  "
            f"conf {f.confidence:.2f}  {preview}",
            file=stdout,
        )
    print(f"Masked: {mask_text(text, findings)}", file=stdout)
    return 0


if __name__ == "__main__":
    for stream in (sys.stdout, sys.stdin):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    raise SystemExit(main())
