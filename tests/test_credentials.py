from gateway.credentials import detect_credentials, shannon_entropy


def types(text):
    return [f.type for f in detect_credentials(text)]


def spans(findings, text):
    return [text[f.start:f.end] for f in findings]


def test_shannon_entropy_empty_and_repeated_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("abcd") == 2.0


def test_detects_aws_access_key_shape():
    text = "AWS key AKIAIOSFODNN7EXAMPLE configured"
    found = detect_credentials(text)
    assert len(found) == 1
    assert found[0].type == "API_KEY"
    assert found[0].category == "CREDENTIAL"
    assert spans(found, text) == ["AKIAIOSFODNN7EXAMPLE"]


def test_detects_contextual_api_key_value():
    text = "api_key = Abcdef1234567890XYZ"
    found = detect_credentials(text)
    assert any(f.type == "API_KEY" and text[f.start:f.end] == "Abcdef1234567890XYZ" for f in found)


def test_detects_password_value_but_not_label():
    text = "password: S3cure!Pass123"
    found = detect_credentials(text)
    assert any(f.type == "PASSWORD" and text[f.start:f.end] == "S3cure!Pass123" for f in found)


def test_password_placeholder_is_not_reported():
    assert not any(f.type == "PASSWORD" for f in detect_credentials("password is required"))
    assert not any(f.type == "PASSWORD" for f in detect_credentials("password: ********"))


def test_detects_bearer_token():
    value = "AbcdEFghIJklMNopQRstUVwxYZ012345"
    text = "Authorization: Bearer " + value
    found = detect_credentials(text)
    assert any(text[f.start:f.end] == value and f.type == "API_KEY" for f in found)


def test_all_findings_have_valid_spans_and_confidence():
    text = "password: P@ssw0rd!234"
    for f in detect_credentials(text):
        assert 0 <= f.start < f.end <= len(text)
        assert 0.0 <= f.confidence <= 1.0
        assert f.category == "CREDENTIAL"


def test_clean_text_has_no_credential_findings():
    assert detect_credentials("Please summarize the meeting notes.") == []
