import io

from detectors.__main__ import main
from detectors.generic_pii import detect_card, detect_email, luhn_valid
from detectors.india_pii import detect_aadhaar
from detectors.scan import detect_all, mask_preview, mask_text
from detectors.verhoeff import is_valid

VISA = "4111111111111111"
VISA_SPACED = "4111 1111 1111 1111"
MASTERCARD = "5555555555554444"
AMEX = "378282246310005"


def make_aadhaar(prefix="23456789012"):
    for check in "0123456789":
        if is_valid(prefix + check):
            return prefix + check


def spans(findings, text):
    return [text[f.start:f.end] for f in findings]


def close(a, b):
    return abs(a - b) < 1e-9


def run_cli(argv=None, stdin_text=""):
    out = io.StringIO()
    code = main(argv, stdin=io.StringIO(stdin_text), stdout=out)
    return code, out.getvalue()


# ---------- Luhn ----------

def test_luhn_known_values():
    assert luhn_valid(VISA) and luhn_valid(MASTERCARD) and luhn_valid(AMEX)
    assert not luhn_valid("4111111111111112")
    assert not luhn_valid("") and not luhn_valid("41a1")


# ---------- Email ----------

def test_email_found_with_exact_offsets():
    text = "write to rahul.k+test@mail.example.co.in please"
    found = detect_email(text)
    assert spans(found, text) == ["rahul.k+test@mail.example.co.in"]
    assert found[0].type == "EMAIL" and found[0].category == "PII"


def test_email_trailing_full_stop_not_included():
    text = "contact rahul@gmail.com."
    assert spans(detect_email(text), text) == ["rahul@gmail.com"]


def test_email_rejects_non_emails():
    assert detect_email("rahul@okaxis") == []
    assert detect_email("price @ 5 dollars") == []
    assert detect_email("no at sign here.com") == []


def test_email_no_raw_value():
    assert "rahul@gmail.com" not in detect_email("rahul@gmail.com")[0].model_dump_json()


# ---------- Card ----------

def test_card_formats_found():
    for number in (VISA, VISA_SPACED, VISA_SPACED.replace(" ", "-"), MASTERCARD, AMEX):
        text = f"pay with {number} now"
        assert spans(detect_card(text), text) == [number], number


def test_card_fields():
    f = detect_card(f"x {VISA}")[0]
    assert f.type == "CARD" and f.category == "FINANCIAL"


def test_card_failing_luhn_ignored():
    assert detect_card("order 4111111111111112") == []
    assert detect_card("order 1234 5678 9012 3456") == []


def test_card_length_limits():
    assert detect_card("123456789012") == []
    assert detect_card(VISA + "1234") == []


def test_card_not_inside_longer_digit_run():
    assert detect_card(f"99{VISA}") == []


def test_card_context_raises_confidence():
    plain = detect_card(f"ref {VISA}")[0].confidence
    with_ctx = detect_card(f"credit card {VISA}")[0].confidence
    assert close(plain, 0.8) and close(with_ctx, 0.95)


def test_card_not_reported_as_aadhaar():
    assert detect_aadhaar(f"card {VISA_SPACED}") == []


def test_card_no_raw_value():
    assert VISA not in detect_card(VISA)[0].model_dump_json()


# ---------- detect_all ----------

def test_detect_all_every_type_in_order():
    a = make_aadhaar()
    text = (
        f"Aadhaar {a}, PAN ABCPE1234F, mobile 9876543210, email rahul@gmail.com, "
        f"card {VISA_SPACED}, GSTIN 27AAPFU0939F1ZV, IFSC SBIN0001234, UPI rahul@okaxis"
    )
    types = [f.type for f in detect_all(text)]
    assert types == ["AADHAAR", "PAN", "PHONE", "EMAIL", "CARD", "GSTIN", "IFSC", "UPI"]


def test_detect_all_phone_inside_email_is_one_finding():
    text = "mail 9876543210@gmail.com"
    assert [f.type for f in detect_all(text)] == ["EMAIL"]


def test_detect_all_clean_text():
    assert detect_all("") == []
    assert detect_all("summarise this report for the team") == []


def test_detect_all_no_overlaps():
    text = f"{VISA} 9876543210 rahul@gmail.com ABCPE1234F rahul@okaxis"
    found = detect_all(text)
    for a, b in zip(found, found[1:]):
        assert a.end <= b.start


# ---------- masking ----------

def test_mask_preview_keeps_last_four_and_separators():
    assert mask_preview("2345 6789 0123") == "XXXX XXXX 0123"
    assert mask_preview("ABCPE1234F") == "XXXXXX234F"
    assert mask_preview("123") == "123"


def test_mask_text_replaces_spans():
    text = "mobile 9876543210 and rahul@gmail.com"
    assert mask_text(text, detect_all(text)) == "mobile [PHONE] and [EMAIL]"


def test_mask_text_without_findings_unchanged():
    assert mask_text("hello world", []) == "hello world"


def test_mask_text_leaves_no_raw_value():
    text = f"card {VISA_SPACED} and phone 9876543210"
    masked = mask_text(text, detect_all(text))
    assert "4111" not in masked and "9876543210" not in masked


# ---------- CLI ----------

def test_cli_reports_findings_with_masked_preview():
    code, out = run_cli(["call", "9876543210", "now"])
    assert code == 0
    assert "Found 1 item(s)" in out
    assert "PHONE" in out and "XXXXXX3210" in out
    assert "Masked: call [PHONE] now" in out
    assert "9876543210" not in out


def test_cli_clean_text():
    code, out = run_cli(["nothing", "sensitive", "here"])
    assert code == 0 and "No sensitive data found." in out


def test_cli_reads_stdin_when_no_args():
    code, out = run_cli([], stdin_text="email rahul@gmail.com")
    assert code == 0 and "EMAIL" in out and "rahul@gmail.com" not in out


def test_cli_never_prints_raw_values():
    a = make_aadhaar()
    code, out = run_cli([f"aadhaar {a} card {VISA}"])
    assert a not in out and VISA not in out
