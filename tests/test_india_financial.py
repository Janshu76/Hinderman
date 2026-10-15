from detectors.india_pii import (
    detect_gstin,
    detect_ifsc,
    detect_india_pii,
    detect_upi,
    gstin_check_char,
)


def make_gstin(state="27", pan="AAPFU0939F", entity="1"):
    body = f"{state}{pan}{entity}Z"
    return body + gstin_check_char(body)


def spans(findings, text):
    return [text[f.start:f.end] for f in findings]


def close(a, b):
    return abs(a - b) < 1e-9


GSTIN = make_gstin()


# ---------- GSTIN ----------

def test_gstin_known_real_world_sample_checksum():
    assert GSTIN == "27AAPFU0939F1ZV"


def test_gstin_found_with_exact_offsets():
    text = f"our gstin is {GSTIN}, thanks"
    found = detect_gstin(text)
    assert spans(found, text) == [GSTIN]
    assert found[0].type == "GSTIN" and found[0].category == "FINANCIAL"


def test_gstin_lowercase_found():
    assert len(detect_gstin(GSTIN.lower())) == 1


def test_gstin_wrong_check_char_ignored():
    wrong = GSTIN[:-1] + ("A" if GSTIN[-1] != "A" else "B")
    assert detect_gstin(wrong) == []


def test_gstin_invalid_state_code_ignored():
    assert detect_gstin(make_gstin(state="50")) == []
    assert detect_gstin(make_gstin(state="00")) == []


def test_gstin_wrong_shape_or_longer_token_ignored():
    assert detect_gstin(GSTIN[:-1]) == []
    assert detect_gstin(GSTIN + "X") == []
    assert detect_gstin("X" + GSTIN) == []
    assert detect_gstin("27AAPFU0939F1YV") == []


def test_gstin_other_valid_state_codes():
    for state in ("07", "29", "33", "97", "99"):
        assert len(detect_gstin(make_gstin(state=state))) == 1, state


def test_gstin_confidence_and_no_raw_value():
    plain = detect_gstin(f"ref {GSTIN}")[0].confidence
    with_ctx = detect_gstin(f"GSTIN {GSTIN}")[0].confidence
    assert close(plain, 0.9) and close(with_ctx, 0.95)
    assert GSTIN not in detect_gstin(GSTIN)[0].model_dump_json()


def test_gstin_not_reported_as_pan_or_phone():
    assert [f.type for f in detect_india_pii(GSTIN)] == ["GSTIN"]


# ---------- IFSC ----------

def test_ifsc_found_with_exact_offsets():
    text = "transfer to SBIN0001234 today"
    found = detect_ifsc(text)
    assert spans(found, text) == ["SBIN0001234"]
    assert found[0].type == "IFSC" and found[0].category == "FINANCIAL"


def test_ifsc_alphanumeric_branch_code():
    assert len(detect_ifsc("HDFC0CAGSBK")) == 1


def test_ifsc_fifth_character_must_be_zero():
    assert detect_ifsc("SBIN1001234") == []


def test_ifsc_wrong_length_or_longer_token_ignored():
    assert detect_ifsc("SBIN000123") == []
    assert detect_ifsc("SBIN00012345") == []
    assert detect_ifsc("XSBIN0001234") == []


def test_ifsc_confidence_levels():
    upper = detect_ifsc("ref SBIN0001234")[0].confidence
    lower = detect_ifsc("ref sbin0001234")[0].confidence
    with_ctx = detect_ifsc("IFSC: sbin0001234")[0].confidence
    assert close(upper, 0.7) and close(lower, 0.5) and close(with_ctx, 0.95)


def test_ifsc_no_raw_value():
    assert "SBIN0001234" not in detect_ifsc("SBIN0001234")[0].model_dump_json()


# ---------- UPI ----------

def test_upi_found_with_exact_offsets():
    text = "pay rahul.k@okaxis now"
    found = detect_upi(text)
    assert spans(found, text) == ["rahul.k@okaxis"]
    assert found[0].type == "UPI" and found[0].category == "FINANCIAL"


def test_upi_phone_number_handle():
    text = "send to 9876543210@ybl"
    assert spans(detect_upi(text), text) == ["9876543210@ybl"]


def test_upi_not_an_email():
    assert detect_upi("mail me at rahul@gmail.com") == []
    assert detect_upi("rahul@company.co.in") == []
    assert detect_upi("rahul@gmail.com.") == []


def test_upi_at_end_of_sentence():
    text = "pay to rahul@okaxis."
    assert spans(detect_upi(text), text) == ["rahul@okaxis"]


def test_upi_handle_too_short_ignored():
    assert detect_upi("a@ybl") == []


def test_upi_confidence_levels():
    known = detect_upi("rahul@okaxis")[0].confidence
    unknown = detect_upi("rahul@somewhere")[0].confidence
    with_ctx = detect_upi("UPI id rahul@somewhere")[0].confidence
    assert close(known, 0.9) and close(unknown, 0.55) and close(with_ctx, 0.95)


def test_upi_no_raw_value():
    assert "rahul@okaxis" not in detect_upi("rahul@okaxis")[0].model_dump_json()


# ---------- combined ----------

def test_combined_phone_inside_upi_is_one_finding():
    text = "send to 9876543210@ybl"
    found = detect_india_pii(text)
    assert [f.type for f in found] == ["UPI"]


def test_combined_standalone_phone_still_found_next_to_upi():
    text = "call 9876543210 or pay rahul@okaxis"
    assert [f.type for f in detect_india_pii(text)] == ["PHONE", "UPI"]


def test_combined_financial_set_in_order():
    text = f"GSTIN {GSTIN}, IFSC SBIN0001234, UPI rahul@okaxis"
    found = detect_india_pii(text)
    assert [f.type for f in found] == ["GSTIN", "IFSC", "UPI"]
    assert spans(found, text) == [GSTIN, "SBIN0001234", "rahul@okaxis"]


def test_combined_no_overlaps_and_sorted():
    text = f"{GSTIN} SBIN0001234 rahul@okaxis 9876543210 ABCPE1234F"
    found = detect_india_pii(text)
    assert [f.start for f in found] == sorted(f.start for f in found)
    for a, b in zip(found, found[1:]):
        assert a.end <= b.start


def test_combined_plain_email_and_text_not_flagged():
    assert detect_india_pii("email rahul@gmail.com about the report") == []
