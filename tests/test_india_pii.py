from detectors.india_pii import (
    detect_aadhaar,
    detect_india_pii,
    detect_pan,
    detect_phone,
)
from detectors.verhoeff import is_valid

VALID_PAN_HOLDER_TYPES = "PCHFATBLJG"


def make_aadhaar(prefix="23456789012"):
    for check in "0123456789":
        if is_valid(prefix + check):
            return prefix + check


def make_bad_aadhaar(prefix="23456789012"):
    for check in "0123456789":
        if not is_valid(prefix + check):
            return prefix + check


def spans(findings, text):
    return [text[f.start:f.end] for f in findings]


def close(a, b):
    return abs(a - b) < 1e-9


AADHAAR = make_aadhaar()
SPACED = f"{AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}"
HYPHENED = SPACED.replace(" ", "-")


# ---------- Aadhaar ----------

def test_aadhaar_plain_spaced_hyphened_found():
    for form in (AADHAAR, SPACED, HYPHENED):
        text = f"my id is {form} thanks"
        found = detect_aadhaar(text)
        assert len(found) == 1
        assert spans(found, text) == [form]


def test_aadhaar_finding_fields():
    f = detect_aadhaar(f"id {AADHAAR}")[0]
    assert f.type == "AADHAAR"
    assert f.category == "PII"
    assert 0 <= f.confidence <= 1


def test_aadhaar_random_twelve_digits_ignored():
    assert detect_aadhaar("order 123456789012") == []


def test_aadhaar_wrong_checksum_ignored():
    assert detect_aadhaar(f"id {make_bad_aadhaar()}") == []


def test_aadhaar_first_digit_zero_or_one_ignored():
    assert detect_aadhaar("0123 4567 8901") == []
    assert detect_aadhaar("1234 5678 9012") == []


def test_aadhaar_inside_card_number_ignored():
    assert detect_aadhaar("card 1234 5678 9012 3456") == []
    assert detect_aadhaar("card 4111 1111 1111 1111") == []


def test_aadhaar_inside_longer_digit_run_ignored():
    assert detect_aadhaar(f"order {AADHAAR}123") == []
    assert detect_aadhaar(f"order 99{AADHAAR}") == []


def test_aadhaar_context_raises_confidence():
    plain = detect_aadhaar(f"id {AADHAAR}")[0].confidence
    with_ctx = detect_aadhaar(f"aadhaar {AADHAAR}")[0].confidence
    assert close(plain, 0.75)
    assert close(with_ctx, 0.95)


def test_aadhaar_two_numbers_both_found():
    other = make_aadhaar("34567890123")
    text = f"{AADHAAR} and {other}"
    assert len(detect_aadhaar(text)) == 2


def test_aadhaar_no_raw_value_in_finding():
    f = detect_aadhaar(f"id {AADHAAR}")[0]
    assert AADHAAR not in f.model_dump_json()


# ---------- PAN ----------

def test_pan_valid_found_with_exact_offsets():
    text = "pan: ABCPE1234F here"
    found = detect_pan(text)
    assert spans(found, text) == ["ABCPE1234F"]
    assert found[0].type == "PAN" and found[0].category == "PII"


def test_pan_every_valid_holder_type_accepted():
    for t in VALID_PAN_HOLDER_TYPES:
        assert len(detect_pan(f"ABC{t}E1234F")) == 1, t


def test_pan_invalid_holder_type_rejected():
    assert detect_pan("ABCXE1234F") == []
    assert detect_pan("ABCDE1234F") == []


def test_pan_holder_type_l_is_valid_shape():
    assert len(detect_pan("HELLO1234X")) == 1


def test_pan_wrong_shape_rejected():
    assert detect_pan("ABCP1234F") == []
    assert detect_pan("ABCPE12345") == []
    assert detect_pan("1BCPE1234F") == []


def test_pan_inside_longer_token_rejected():
    assert detect_pan("XABCPE1234F") == []
    assert detect_pan("ABCPE1234FX") == []


def test_pan_lowercase_found_with_lower_confidence():
    upper = detect_pan("ref ABCPE1234F")[0].confidence
    lower = detect_pan("ref abcpe1234f")[0].confidence
    assert lower < upper
    assert close(upper, 0.85)
    assert close(lower, 0.6)


def test_pan_context_raises_confidence():
    plain = detect_pan("ref ABCPE1234F")[0].confidence
    with_ctx = detect_pan("my PAN is ABCPE1234F")[0].confidence
    assert with_ctx > plain
    assert close(with_ctx, 0.95)


def test_pan_offsets_survive_length_changing_characters():
    text = "straße ABCPE1234F"
    f = detect_pan(text)[0]
    assert text[f.start:f.end] == "ABCPE1234F"


def test_pan_no_raw_value_in_finding():
    f = detect_pan("ABCPE1234F")[0]
    assert "ABCPE1234F" not in f.model_dump_json()


# ---------- Phone ----------

def test_phone_formats_found():
    cases = {
        "call 9876543210 now": "9876543210",
        "reach +91 98765 43210": "+91 98765 43210",
        "ph 98765-43210": "98765-43210",
        "919876543210": "919876543210",
        "09876543210": "09876543210",
    }
    for text, expected in cases.items():
        assert spans(detect_phone(text), text) == [expected], text


def test_phone_must_start_with_6_to_9():
    assert detect_phone("number 5876543210") == []
    assert detect_phone("number 1234567890") == []


def test_phone_not_inside_longer_number():
    assert detect_phone("order 98765432101234") == []
    assert detect_phone("card 4111 1111 1111 1111") == []


def test_phone_not_reported_inside_valid_aadhaar():
    assert detect_phone(f"aadhaar {AADHAAR}") == []


def test_phone_confidence_levels():
    bare = detect_phone("ref 9876543210")[0].confidence
    prefixed = detect_phone("ref +919876543210")[0].confidence
    with_ctx = detect_phone("mobile: 9876543210")[0].confidence
    assert close(bare, 0.6)
    assert close(prefixed, 0.85)
    assert close(with_ctx, 0.95)


def test_phone_finding_fields_and_no_raw_value():
    f = detect_phone("call 9876543210")[0]
    assert f.type == "PHONE" and f.category == "PII"
    assert "9876543210" not in f.model_dump_json()


# ---------- detect_india_pii (combined) ----------

def test_combined_finds_all_three_in_order():
    text = f"Aadhaar {AADHAAR}, PAN ABCPE1234F, mobile +91 98765 43210"
    found = detect_india_pii(text)
    assert [f.type for f in found] == ["AADHAAR", "PAN", "PHONE"]
    assert spans(found, text) == [AADHAAR, "ABCPE1234F", "+91 98765 43210"]


def test_combined_sorted_by_position_even_when_reversed():
    text = f"call 9876543210 then ABCPE1234F then {AADHAAR}"
    found = detect_india_pii(text)
    assert [f.type for f in found] == ["PHONE", "PAN", "AADHAAR"]
    assert [f.start for f in found] == sorted(f.start for f in found)


def test_combined_clean_and_empty_text():
    assert detect_india_pii("") == []
    assert detect_india_pii("please summarise the quarterly report") == []


def test_combined_look_alikes_not_flagged():
    text = "order 123456789012 card 4111 1111 1111 1111 code ABCXE1234F ref 5876543210"
    assert detect_india_pii(text) == []


def test_combined_aadhaar_not_double_reported_as_phone():
    found = detect_india_pii(f"aadhaar {AADHAAR}")
    assert [f.type for f in found] == ["AADHAAR"]


def test_combined_findings_never_overlap():
    text = f"{AADHAAR} ABCPE1234F 9876543210 {SPACED}"
    found = detect_india_pii(text)
    for a, b in zip(found, found[1:]):
        assert a.end <= b.start


def test_combined_confidence_in_range_and_no_raw_values():
    text = f"Aadhaar {AADHAAR}, PAN ABCPE1234F, mobile 9876543210"
    for f in detect_india_pii(text):
        assert 0 <= f.confidence <= 1
        dumped = f.model_dump_json()
        for raw in (AADHAAR, "ABCPE1234F", "9876543210"):
            assert raw not in dumped


def test_combined_repeated_value_found_each_time():
    text = "9876543210 and again 9876543210"
    assert len(detect_india_pii(text)) == 2
