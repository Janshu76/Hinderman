"""Run all three scenarios live, plus the offline document check. Prints a summary table.

    python -m redteam.run_demo

Needs the gateway running, the test logins in .env, and the poisoned PDF built.
"""
import sys

from injection import scorer
from redteam.poisoned.make_poisoned_pdf import build, extracted_text, verify
from redteam.scenarios import s1_accidental_pii, s2_injection_extraction, s3_unauthorised_rag


def poisoned_document_check() -> bool:
    """Offline: the scanner must flag the hidden instruction in the extracted text."""
    result = scorer.score(extracted_text(), "document")
    print("=" * 72)
    print("Offline: poisoned PDF through the document scanner")
    print(f"Score {result.score:.2f} -> {result.label}")
    for reason in result.reasons:
        print(f"  - {reason}")
    passed = result.label == "injection"
    print(f"RESULT: {'PASS' if passed else 'FAIL'}")
    return passed


def guarded(name: str, fn) -> bool:
    try:
        return fn()
    except Exception as exc:          # gateway down, bad login, and so on: record it, keep going
        print(f"{name}: ERROR {type(exc).__name__}: {exc}")
        return False


def main() -> int:
    build()
    if not verify():
        print("Hidden text is not extractable from the PDF. Check reportlab and pypdf versions.")
        return 1

    results = {
        "1 accidental PII (mask)": guarded("s1", s1_accidental_pii.run),
        "2 injection extraction (block)": guarded("s2", s2_injection_extraction.run),
        "3 unauthorised RAG (deny / allow)": guarded("s3", s3_unauthorised_rag.run),
        "offline poisoned PDF (scanner)": guarded("doc", poisoned_document_check),
    }

    print("\n" + "=" * 72)
    print("DEMO SUMMARY")
    for name, passed in results.items():
        print(f"  {'PASS' if passed else 'FAIL'}  {name}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())